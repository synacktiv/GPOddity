import socket
import sys
import _thread as thread
import time

def server(*settings):
    try:
        msg = f" - client is querying its GPT (SMB), forwarding to {settings[2]}:{settings[3]}"
        dock_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dock_socket.bind((settings[0], settings[1]))
        dock_socket.listen(5)
        while True:
            client_socket, upstream_addr = dock_socket.accept()
            print(f"[FORWARDER] Incoming connection from {upstream_addr}" + msg)
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((settings[2], settings[3]))
            thread.start_new_thread(forward, (client_socket, server_socket))
            thread.start_new_thread(forward, (server_socket, client_socket))
    finally:
        thread.start_new_thread(server, settings)

def forward(source, destination):
    string = ' '
    while string:
        try:
            string = source.recv(1024)
            if string:
                destination.sendall(string)
            else:
                raise ConnectionResetError()
        except ConnectionResetError:
            pass