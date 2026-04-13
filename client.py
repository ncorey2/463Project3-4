import socket
import threading

## This Program acts as the Client for a "chat" room for the CSCE 463 Project 3/4

def client_connection(name, port):
    client_socket = socket.socket()
    client_socket.connect((name, port))
    return client_socket


def receive_messages(sock):
    """Continuously listens for incoming messages from the server."""
    try:
        while True:
            message = sock.recv(1024).decode()
            if not message:
                break
            print(f"\n{message}")
    except Exception as e:
        print("Connection lost:", e)


def send_messages(sock, client_name):
    """Continuously waits for user input and sends it to the server."""
    try:
        while True:
            client_input = input(f"{client_name}: ")
            sock.send(f"{client_name}: {client_input}".encode())
    except Exception as e:
        print("An error has occured:", e)


def client_send(sock, client_name):
    # Exchange names with server
    sock.send(client_name.encode())
    server_name = sock.recv(1024).decode()
    print(f"Connected to server: {server_name}")
    print("You can now send messages freely.\n")

    # Spin up one thread for receiving, one for sending
    recv_thread = threading.Thread(target=receive_messages, args=(sock,))
    send_thread = threading.Thread(target=send_messages, args=(sock, client_name))
    recv_thread.daemon = True
    send_thread.daemon = True
    recv_thread.start()
    send_thread.start()

    # Keep main thread alive while the two above run
    recv_thread.join()


# Information
name = input('Enter Server IP address: ')
client_name = input('Enter your name: ')
port = 8080
client_socket = client_connection(name, port)
client_send(client_socket, client_name)