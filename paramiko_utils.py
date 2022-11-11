#!/usr/bin/env python3
#
# Utilities and helper functions for Paramiko.
#
# Unfortunately Paramiko is missing some very trivial
# functionality, so this library tries to help with that.
#
# TODO: The sftp module should be drastically improved!
# Glob patterns, option to ignore error if destination exists, etc.
#
import base64
import binascii
from hashlib import md5, sha1
import io
import logging
import socket
import sys
import threading

from paramiko.client import MissingHostKeyPolicy, SSHClient
from paramiko.dsskey import DSSKey
from paramiko.ecdsakey import ECDSAKey
from paramiko.ed25519key import Ed25519Key
from paramiko.pkey import PublicBlob
from paramiko.rsakey import RSAKey
from paramiko.ssh_exception import SSHException

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# https://github.com/paramiko/paramiko/blob/main/paramiko/transport.py#L151
_KEY_TYPE_TO_CLASS = {
    'ssh-ed25519': Ed25519Key,
    'ecdsa-sha2-nistp256': ECDSAKey,
    'ecdsa-sha2-nistp384': ECDSAKey,
    'ecdsa-sha2-nistp521': ECDSAKey,
    'ssh-rsa': RSAKey,
    'ssh-dss': DSSKey}
_KEY_TYPES   = list(set(_KEY_TYPE_TO_CLASS.keys()))
_KEY_CLASSES = list(set(_KEY_TYPE_TO_CLASS.values()))


class CallbackClient(SSHClient):
    """
    Wrapper around SSHClient with extra callback functions.
    This helps if the client connection relies on resources
    that need to be acquired and released manually (e.g. sockets).
    """
    # TODO: How should __init__ take *args and **kwargs?
    def __init__(self, start_cb=None, stop_cb=None):
        self._start_cb = start_cb or (lambda: None)
        self._stop_cb = stop_cb or (lambda: None)
        super().__init__()

    def connect(self, *args, **kwargs):
        # Notify the manager that the connection has started.
        self._start_cb()
        super().connect(*args, **kwargs)

    def close(self, *args, **kwargs):
        super().close(*args, **kwargs)
        # Notify the manager that the connection has ended.
        self._stop_cb()


# TODO: There are some simplifications
#   - Recognize different key type naming conventions (RSA, rsa, ssh-rsa, etc.)
#   - Hosts could appear differently (hostname, IP address, hashed).
class VerifyFingerprintPolicy(MissingHostKeyPolicy):
    """
    Supply a list of host key fingerprints to verify against.
    Each fingerprint should be a (hostname, key_type, hash_string) triple.
    Supported hash algorithms: MD5, SHA1.
    The hash can start with an optional '<hash_algo>:' prefix.
    Hexadecimal hashes can contain ':' characters as separators.
    """
    def __init__(self, fingerprints):
        self._fingerprints = {
            y[0]:[self._process_hash(x[2])
                  for x in fingerprints if x[0] == y[0]]
            for y in fingerprints}
        super().__init__()

    def _process_hash(self, string):
        """
        Remove unneeded parts, and convert from string
        to bytes format (based on hex / base64 representation).
        """
        if any(string.startswith(a) for a in ('MD5:', 'SHA1:')):
            string = string.split(':', 1)
        string.replace(':', '')
        try:
            return bytes.fromhex(string)
        except:
            try:
                string += '=' * (4 - (len(string) % 4))  # Add padding.
                return base64.b64decode(string.encode())
            except:
                raise ValueError(f'Invalid fingerprint hash: {string}')

    def _get_hashes(self, data):
        yield md5(data).digest()
        yield sha1(data).digest()

    def missing_host_key(self, client, hostname, key):
        if any(hash in self._fingerprints[hostname]
               for hash in self._get_hashes(key.asbytes())):
            client._host_keys.add(hostname, key.get_name(), key)
            client._log(logging.DEBUG,
                f'Adding {key.get_name()} host key for {hostname}: '
                f'MD5:{binascii.hexlify(key.get_fingerprint())}')
        else:
            raise SSHException(
                f'Server {hostname} has invalid fingerprint:'
                f' {key.get_name()} {key.get_base64()}')


def interactive_shell(chan):
    """
    This code is part of Paramiko / demos / interactive.py.

    Opens an interactive remote session over SSH.
    A line-buffered terminal emulator. Pressing F6 or ^Z will send EOF.
    Example use: interactive_shell(client.invoke_shell())

    It's not the fastest thing ever, special character codes probably don't
    work at all (e.g. pressing up for previous commands). Passwords are not
    hidden when typed. Otherwise, works like a charm.
    """
    # TODO: The posix shell example is better, because it uses select, etc.!
    def _writeall(sock):
        while True:
            data = sock.recv(4096)
            if not data:
                sys.stdout.write('\n')
                sys.stdout.flush()
                break
            sys.stdout.write(data.decode())
            sys.stdout.flush()
    threading.Thread(target=_writeall, args=(chan,)).start()
    try:
        while True:
            data = sys.stdin.read(1)
            if not data:
                break
            chan.send(data)
    except EOFError:  # F6 or ^Z sends EOF to stdin.
        pass


def public_key_from_string(string):
    """
    Return a PKey subclass instance containing the public part of the string.
    The string should be the exact content of an id_*.pub file, with
    the key type, base 64 key data and optional final comments.
    """
    blob = PublicBlob.from_string(string)
    assert blob.key_type in _KEY_TYPES, f'Unknown key type {blob.key_type}'
    return _KEY_TYPE_TO_CLASS[blob.key_type](data=blob.key_blob)


def public_key_to_string(pkey, comment=""):
    """
    Return the string representation of a public key as in an id_*.pub file.
    """
    return f'{pkey.get_name()} {pkey.get_base64()} {comment}'


def private_key_from_string(string):
    """
    Return a PKey subclass instance from the private key in the string.
    The string should be the exact content of an id_* (e.g. id_rsa) file.
    """
    for cls in _KEY_CLASSES:
        try:
            return cls.from_private_key(io.StringIO(string))
        except SSHException:
            pass
    raise SSHException(f'Unable to parse private key from string {string}')
