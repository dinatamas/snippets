#!/usr/bin/env python3
"""
A simple TCP proxy server.

Sources:
  - https://steelkiwi.com/blog/working-tcp-sockets/
  - https://realpython.com/python-sockets/
  - https://voorloopnul.com/blog/a-python-proxy-in-less-than-100-lines-of-code/
  - https://github.com/techalchemy/python-proxyserver
  - https://medium.com/@gdieu/build-a-tcp-proxy-in-python-part-1-3-7552cd5afdfe

Usage:
  - ./proxy.py 127.0.0.1 24441 0.0.0.0 24442: Start proxy.
  - ncat -v 0.0.0.0 24441: Send data to be forwarded.
  - ncat -v -l -k -p 24442: Listen to forwarded data.

up_hook = lambda: None
c2s_hook = lambda msg: None
s2c_hook = lambda msg: None
down_hook = lambda: None

try:
    run_proxy_server(
        '127.0.0.1', 24441,
        'itechchallenge.dyndns.org', 11224,
        up_hook, c2s_hook, s2c_hook, down_hook)
except KeyboardInterrupt:
    logging.info('Keyboard interrupt received, terminating')
"""
import argparse
import logging
import select
import socket
import queue


class TCPPeer:
    """
    Common base class for TCPClient and TCPServer.
    To read from the peer call `read()`.
    To write to the peer put the data to `queue` and call `flush()`.
    Before deleting the object, call `sock.close()`!
    """
    def __init__(self, sock, host, port, hook):
        self.sock = sock
        self.host = host
        self.port = port
        self.queue = queue.Queue()
        self.hook = hook

    def flush(self):
        """Sends all available data to the peer."""
        while not self.queue.empty():
            msg = self.hook(self.queue.get_nowait())
            self.sock.sendall(msg)

    def read(self):
        """Reads all available data from the peer."""
        return self.sock.recv(4096)  # TODO: Read all data.


class TCPClient(TCPPeer):
    def __init__(self, conn, addr, s2c_hook):
        TCPPeer.__init__(self, conn, addr[0], addr[1], s2c_hook)


class TCPServer(TCPPeer):
    def __init__(self, host, port, c2s_hook):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.connect((host, port))
        logging.info('Connected to server')
        sock.setblocking(False)
        TCPPeer.__init__(self, sock, host, port, c2s_hook)


def run_proxy_server(
        bind_host, bind_port,
        dest_host, dest_port,
        up_hook, c2s_hook, s2c_hook, down_hook):
    """
    Perform setup and listen forever.
    Hooks:
      - up_hook: Called when client-proxy-server connection is established.
      - c2s_hook: Called for each client-to-server message.
      - s2c_hook: Called for each server-to-client message.
      - down_hook: Called when the client-proxy-server connection is closed.
    """
    # Create socket to receive client connections on.
    bind_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bind_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bind_sock.setblocking(False)

    # Start listening for client connections.
    bind_sock.bind((bind_host, bind_port))
    bind_sock.listen()
    logging.info(f'Listening on {(bind_host, bind_port)}')

    server = None
    client = None

    inputs = [bind_sock]
    outputs = []

    # Main loop.
    while True:
        readable, writable, in_error = select.select(inputs, outputs, [])
        for sock in readable:
            if sock is bind_sock:
                if not client:
                    # Accept the connection if there's no client yet.
                    conn, addr = bind_sock.accept()
                    logging.info(f'Connection opened by client at {addr}')
                    conn.setblocking(False)
                    client = TCPClient(conn, addr, s2c_hook)
                    # We will read/write from/to the client.
                    inputs.append(client.sock)
                    outputs.append(client.sock)
                    # Connect to the server.
                    # TODO: If server is down, log it and drop client.
                    server = TCPServer(dest_host, dest_port, c2s_hook)
                    # We will read/write from/to the server.
                    inputs.append(server.sock)
                    outputs.append(server.sock)
                    # Call setup hook.
                    up_hook()
            if sock is server.sock:
                data = server.read()
                if data:
                    # Write to client what we read from server.
                    client.queue.put(data)
                else:
                    # If socket is readable but receives 0 bytes,
                    # the server disconnected.
                    inputs.remove(server.sock)
                    outputs.remove(server.sock)
                    server.sock.close()
                    server = None
                    logging.info('Connection closed by server.')
            if sock is client.sock:
                data = client.read()
                if data:
                    # Write to server what we read from client.
                    server.queue.put(data)
                else:
                    # If socket is readable but receives 0 bytes,
                    # the client disconnected.
                    inputs.remove(client.sock)
                    outputs.remove(client.sock)
                    client.sock.close()
                    client = None
                    down_hook()
                    logging.info('Connection closed by client')

        for sock in writable:
            if client and sock is client.sock:
                client.flush()
                # If server is closed, close the client too.
                if not server:
                    inputs.remove(client.sock)
                    outputs.remove(client.sock)
                    client.sock.close()
                    client = None
                    down_hook()
                    logging.info('Connection to client closed')
            if server and sock is server.sock:
                server.flush()
                # If client is closed, close the server too.
                if not client:
                    inputs.remove(server.sock)
                    outputs.remove(server.sock)
                    server.sock.close()
                    server = None
                    logging.info('Connection to server closed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('bind_host')
    parser.add_argument('bind_port', type=int)
    parser.add_argument('dest_host')
    parser.add_argument('dest_port', type=int)
    parser.print_help = lambda: print('''\
Usage: proxy.py [-h] bind_host bind_port dest_host dest_port

Simple TCP proxy server.
Listens on bind_host:bind_port until a client connects.
Then all traffic from the client will be forwarded to dest_host:dest_port,
and all traffic from dest_host:dest_port will be forwarded back to the client.
If either side breaks the connection, then the proxy will close
the other one too after sending all messages from its queue.
Only one client connection is allowed at a time.

Positional arguments:
  bind_host     Hostname or IP to listen on.
  bind_port     Port on bind_host to listen on.
  dest_host     Hostname or IP to forward to.
  dest_port     Port on dest_host to forward to.

Optional arguments:
  -h, --help    Show this help message and exit''')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)

    def c2s_print_hook(msg):
        print(f'C2S: {msg.decode("utf-8")}', end='')
        return msg

    def s2c_print_hook(msg):
        print(f'S2C: {msg.decode("utf-8")}', end='')
        return msg

    up_hook = lambda: None
    c2s_hook = c2s_print_hook
    s2c_hook = s2c_print_hook
    down_hook = lambda: None

    try:
        run_proxy_server(
            args.bind_host, args.bind_port,
            args.dest_host, args.dest_port,
            up_hook, c2s_hook, s2c_hook, down_hook)
    except KeyboardInterrupt:
        logging.info('Keyboard interrupt received, terminating')
