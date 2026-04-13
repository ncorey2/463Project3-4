import socket
import threading

## This Program acts as the Server for a "chat" room for the CSCE 463 Project 3/4

# Setting up the chat room
chat_socket = socket.socket()
chat_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
host_name = socket.gethostname()
s_ip = socket.gethostbyname(host_name)
port = 8080
chat_socket.bind((host_name, port))


def receive_messages(connection, client_name):
    """Continuously listens for incoming messages from the client."""
    try:
        while True:
            message = connection.recv(1024).decode()
            if not message:
                break
            print(f"\n{message}")
    except Exception as e:
        print("Connection lost:", e)


def send_messages(connection, server_name):
    """Continuously waits for server operator input and sends it to the client."""
    try:
        while True:
            my_input = input(f"{server_name}: ")
            connection.send(f"{server_name}: {my_input}".encode())
    except Exception as e:
        print("An error has occured:", e)


def talk_with_client(connection, address):
    try:
        print("Recieved connection from", address[0])

        # Exchange names
        client_name = connection.recv(1024).decode()
        print(client_name, "has connected.")
        server_name = input("Enter your name: ")
        connection.send(server_name.encode())

        print("You can now send messages freely.\n")

        # Spin up one thread for receiving, one for sending
        recv_thread = threading.Thread(target=receive_messages, args=(connection, client_name))
        send_thread = threading.Thread(target=send_messages, args=(connection, server_name))
        recv_thread.daemon = True
        send_thread.daemon = True
        recv_thread.start()
        send_thread.start()

        # Keep this thread alive while the two above run
        recv_thread.join()

    except Exception as e:
        print("An error has occured:", e)


try:
    print("Welcome to Chat\n")
    print("Binding was successfull!")
    print("Your IP =", s_ip)
    chat_socket.listen(5)

    while True:
        connection, add = chat_socket.accept()
        new_connection = threading.Thread(target=talk_with_client, args=(connection, add))
        new_connection.start()

except Exception as e:
    print("An error has occured:", e)