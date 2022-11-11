#!/usr/bin/env python3
#
# Linode management library.
#
# CLI API:
#   List, view, create, and delete Linodes with simple commands.
#   Requires the LINODE_TOKEN environment variable to be set.
#   Linode credentials can be persisted in the linodes.json file.
#
# Library API:
#   LinodeClient: Bindings for the Linode HTTP API.
#   LinodeInstance: Control an individual Linode instance.
#   LishClient: Bindings for the Linode Lish Console.
#
import argparse
import json
import logging
import os
import secrets
import time

from paramiko.client import SSHClient, WarningPolicy
from paramiko.pkey import PKey
from paramiko.ssh_exception import SSHException
import requests

from paramiko_utils import (
    public_key_from_string,
    public_key_to_string,
    VerifyFingerprintPolicy)

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

LISH_FINGERPRINTS = list(zip(
    ('lish-frankfurt.linode.com',) * 4,
    ('RSA', 'ECDSA', 'Ed25519', 'Ed25519'),
    ('437622430e01cb846a80b99b9034c7b1',
     'e1FxEXiZVi6n13tagd1ZAQEW/fsRqz29ez5IfWf9kxg',
     'vG1rnoGe7XRRY0nauJREQk75OamxCwRRpeaTDB8LpgM',
     '9e8386e2f9f7f756fcbf54bb757e7937')))

LINODE_API = 'https://api.linode.com/v4/linode'
LINODES_FILE = 'linodes.json'

HELP = '''\
Usage: linode.py [-h] <command> [<args>]

Commands:
  create <label> <pubkey> [<passwd>]
    Create and start a new Linode with the given label and credentials.

  get [<label>]
    Retrieve the details of a Linode if <label> is specified,
    get the list of all Linodes otherwise.

  delete <label>
    Stop and delete the Linode with the given label.

Optional arguments:
  -h, --help    Show this help message and exit.'''


class LinodeClient:
    """
    Wrapper around the Linode HTTP API.
    Requires a Personal Access Token.
    """
    def __init__(self, token):
        self._token = token

    @property
    def auth_header(self):
        return {'Authorization': f'Bearer {self._token}'}

    def get_linode(self, nodeid):
        resp = requests.get(
            f'{LINODE_API}/instances/{nodeid}/',
            headers=self.auth_header)
        resp.raise_for_status()
        return resp.json()

    def get_linodes(self):
        resp = requests.get(
            f'{LINODE_API}/instances/',
            headers=self.auth_header)
        resp.raise_for_status()
        return resp.json()['data']

    def get_linode_by_label(self, label):
        return next((l for l in self.get_linodes()
                     if l['label'] == label), None)

    def create_linode(self, label, public_key: str, passwd):
        linode_config = {
            'authorized_keys': [public_key],
            'backups_enabled': False,
            'booted': True,
            'image': 'linode/ubuntu20.04',
            **({'label': label} if label else {}),
            'region': 'eu-central',
            'root_pass': passwd,
            'type': 'g6-standard-6'}
        resp = requests.post(
            f'{LINODE_API}/instances/',
            headers={'Content-Type': 'application/json', **self.auth_header},
            json=linode_config)
        resp.raise_for_status()
        return resp.json()

    def delete_linode(self, nodeid):
        resp = requests.delete(
            f'{LINODE_API}/instances/{nodeid}/',
            headers=self.auth_header)
        resp.raise_for_status()

    def delete_linode_by_label(self, label):
        linode = self.get_linode_by_label(label)
        assert linode, f'No instance with label {label}'
        self.delete_linode(linode['id'])


class LinodeInstance:
    """
    Manage a single Linode instance (identified by a label).
    As a context manager it will create/delete the instance upon entry/exit.
    Requires a LinodeClient to perform administrative actions.
    """
    def __init__(self, client, label=None):
        self._client = client
        self.label = label
        # The following attributes don't have to be
        # filled at all times. They may be set as inputs
        # for the methods (e.g. credentials for create())
        # or as a result to reflect the remote instance's
        # state (e.g. the IP as returned by get()).
        self.nodeid = None
        self.ipv4 = None
        self.passwd = None
        self.ssh_key: PKey = None
        self.host_key: PKey = None
        if label:
            self._update_self(self._client.get_linode_by_label(self.label))
        self.load()

    def __str__(self):
        linode = json.loads(json.dumps(
            self.__dict__,
            default=lambda o: repr(o)))
        linode['ssh_key'] = self.ssh_key.get_base64()
        return json.dumps(linode)

    def save(self):
        if not self.nodeid:
            return None
        try:
            with open(LINODES_FILE, 'r') as f:
                linodes = json.loads(f.read())
        except FileNotFoundError:
            linodes = {}
        if self.nodeid not in linodes:
            linodes[self.nodeid] = {}
        if self.passwd:
            linodes[self.nodeid]['passwd'] = self.passwd
        if self.host_key:
            linodes[self.nodeid]['host_key'] = \
                public_key_to_string(self.host_key)
        with open(LINODES_FILE, 'w') as f:
            f.write(json.dumps(linodes))
        return self

    def load(self):
        try:
            with open(LINODES_FILE, 'r') as f:
                linodes = json.loads(f.read())
        except FileNotFoundError:
            return None
        if self.nodeid in linodes:
            if 'passwd' in linodes[self.nodeid]:
                self.passwd = linodes[self.nodeid]['passwd']
            if 'host_key' in linodes[self.nodeid]:
                self.host_key = public_key_from_string(
                    linodes[self.nodeid]['host_key'])
        return self

    def _update_self(self, linode):
        if not linode:
            self.nodeid = None
            self.ipv4 = None
        else:
            self.nodeid = str(linode['id'])
            self.ipv4 = linode['ipv4'][0]
        self.save()
        return self

    def get(self):
        linode = self._client.get_linode(self.nodeid)
        return self._update_self(linode)

    def create(self):
        assert not self.nodeid, f'Linode {self.label} already exists'
        assert self.ssh_key, f'No SSH key provided for Linode {self.label}'
        assert self.passwd, f'No password provided for Linode {self.label}'
        logger.debug(f'Creating new Linode: {str(self)}')
        linode = self._client.create_linode(
            self.label, public_key_to_string(self.ssh_key), self.passwd)
        logger.info(f'Linode {self.label} created')
        self.save()
        return self._update_self(linode)

    def wait(self, timeout=60):
        assert self.nodeid, f'Linode {self.label} does not exist'
        logger.debug(f'Checking if Linode {self.label} is running')
        for _ in range(timeout):
            if self._client.get_linode(self.nodeid)['status'] == 'running':
                break
            time.sleep(1)
        else:
            raise TimeoutError('Operation timed out')
        logger.debug(f'Linode {self.label} is running')
        return self

    def delete(self):
        assert self.nodeid, f'Linode {self.label} does not exist'
        self._client.delete_linode(self.nodeid)
        logger.info(f'Linode {self.label} deleted')
        try:
            with open(LINODES_FILE, 'r') as f:
                linodes = json.loads(f.read())
            if self.nodeid in linodes:
                del linodes[self.nodeid]
            with open(LINODES_FILE, 'w') as f:
                f.write(json.dumps(linodes))
        except FileNotFoundError:
            pass
        return self._update_self(None)

    def __enter__(self):
        """
        To connect there are two context managers can be used.
        The outer one is this, where the instance is created and deleted.
        The inner one is the SSHClient (session) returned by connect().
        """
        if not self.nodeid:
            self.create()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.nodeid:
            self.delete()

    def connect(self):
        assert self.nodeid, f'Linode {self.label} does not exist'
        assert self.ssh_key, f'No SSH key provided for Linode {self.label}'
        assert self.passwd, f'No password provided for Linode {self.label}'
        self.wait()
        conn = SSHClient()
        if self.host_key:
            conn._host_keys.add(
                self.ipv4, self.host_key.get_name(), self.host_key)
        else:
            conn.set_missing_host_key_policy(WarningPolicy)
        conn.connect(
            hostname=self.ipv4,
            port=22,
            username='root',
            password=self.passwd,
            pkey=self.ssh_key,
            allow_agent=False,
            look_for_keys=False,
            timeout=30.0,
            banner_timeout=30.0,
            auth_timeout=30.0)
        return conn


class LishClient(SSHClient):
    """
    Interact with the Linode Lish Console.
    This is essentially an SSHClient that is already connected to
    the Lish gateway. There are utility functions to easily execute
    commands (since there are only a handful allowed).
    """
    def __init__(self, user, ssh_key):
        self.user = user
        self.ssh_key = ssh_key

    # Note:
    # The implementation of this method is very sketchy.
    # This relies on raw TCP sockets, which is unfortunate
    # because there is no way to interact with the process directly,
    # only to send and recv data to/from the server.
    # The TCP connection is stream-based, not message-based, so
    # in this case there is no way to really know that all of
    # the data has been read from the server.
    # As a heuristic, shell prompts are used as separators.
    def exec_linode_command(self, label, passwd, command):
        """
        Connect to a Linode instance via Lish and execute the given command.
        This can be useful to perform steps that are needed before a
        direct SSH connection can be established
        (e.g. because its host fingerprint is not yet known).
        Returns an (exit_status, output) pair where output is the
        combined stdout+stderr of the command.

        TODO: Current limitation requires that the command prints a final
              newline. If that is not the case then the last line
              of the command's output is written between the ASCII
              escape chars and the root@ part of the prompt. A regular
              expression has to match that area and skip accordingly.
        """
        conn = SSHClient()
        conn.set_missing_host_key_policy(
            VerifyFingerprintPolicy(LISH_FINGERPRINTS))
        conn.connect(
            hostname='lish-frankfurt.linode.com',
            port=22,
            username=self.user,
            pkey=self.ssh_key,
            allow_agent=False,
            look_for_keys=False,
            timeout=30.0,
            banner_timeout=30.0,
            auth_timeout=30.0)

        # TODO: Rewrite with select!
        channel = conn.invoke_shell()
        channel.setblocking(True)

        def _wait_for_server(prompts, timeout=60):
            """
            Read until one of the prompts is received from the server.
            Returns the (prompt_num, data) pair or raises a TimeoutError.
            """
            data = b''
            for _ in range(timeout):
                time.sleep(1)
                while channel.recv_ready():
                    part = channel.recv(4096)
                    data += part
                for i, prompt in enumerate(prompts):
                    if data.endswith(prompt):
                        return i, data[:-len(prompt)]
            raise TimeoutError(f'No prompt received, only {data}')

        def _wait_for_lish(timeout=60):
            return _wait_for_server(
                prompts=[f'[{self.user}@lish-frankfurt.linode.com]# '.encode()],
                timeout=timeout)[1].decode()

        def _wait_for_linode(timeout=60):
            return _wait_for_server(
                prompts=[
                    b'\x1b[H\x1b[24;80H\rroot@localhost:~# ',
                    b'root@localhost:~# '],
                timeout=timeout)[1]

        def _is_login(timeout=60):
            return _wait_for_server(
                prompts=[
                    b'localhost login: ',
                    b'\x1b[H\x1b[24;80H\rroot@localhost:~# ',
                    b'root@localhost:~# '],
                timeout=timeout)[0] == 0  # First prompt was successful.

        # TODO: Add the proper amount of debugging!
        _wait_for_lish()
        assert channel.send(f'{label}\n'.encode())
        if _is_login():
            assert channel.send(b'root\n')
            assert channel.send(f'{passwd}\n'.encode())
            _wait_for_linode()
        assert channel.send(f'{command}\n'.encode())
        # First the command itself is read back, so skip that.
        output = _wait_for_linode()[len(f'{command}\r\n'):]
        channel.send(b'echo $?\n')
        # For the exit status also escape the final newlines from echo.
        exit_status = _wait_for_linode()[len('echo $?\r\n'):-len('\r\n')]
        channel.send(b'exit\n')
        channel.close()
        return int(exit_status), output.decode()

    def get_linode_host_key(self, label, passwd):
        """
        Return the public host key of
        the Linode instance with the given label.
        """
        exit_status, output = self.exec_linode_command(
            label=label, passwd=passwd,
            command='cat /etc/ssh/ssh_host_ed25519_key.pub')
        if exit_status != 0:
            raise SSHException(
               f'Unable to fetch Linode {label} host key:'
               f' exit code {exit_status}, output: {output}')
        return public_key_from_string(output)


if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger(__name__).setLevel(logging.INFO)

    parser = argparse.ArgumentParser()
    parser.print_help = lambda: print(HELP)
    subparsers = parser.add_subparsers(dest='command')
    create_parser = subparsers.add_parser('create')
    create_parser.add_argument('label')
    create_parser.add_argument('pubkey')
    create_parser.add_argument('passwd', nargs='?')
    get_parser = subparsers.add_parser('get')
    create_parser.print_help = lambda: print(HELP)
    get_parser.add_argument('label', nargs='?')
    get_parser.print_help = lambda: print(HELP)
    delete_parser = subparsers.add_parser('delete')
    delete_parser.add_argument('label')
    delete_parser.print_help = lambda: print(HELP)

    args = parser.parse_args()

    assert (token := os.getenv('LINODE_TOKEN'))
    client = LinodeClient(token)

    if args.command == 'create':
        with open(args.pubkey, 'r') as f:
            pubkey = public_key_from_string(f.read()[:-1])
        passwd = args.passwd or secrets.token_urlsafe(30)
        if not args.passwd:
            logger.info(f'Instance {args.label} will have password: {passwd}')
        linode = LinodeInstance(client, args.label)
        linode.passwd = passwd
        linode.ssh_key = pubkey
        linode.create()
    elif args.command == 'get':
        if args.label:
            print(json.dumps(client.get_linode_by_label(args.label)))
        else:
            print(json.dumps(client.get_linodes()))
    elif args.command == 'delete':
        linode = LinodeInstance(client, args.label).delete()
