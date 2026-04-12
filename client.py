import socket

## This Program acts as the Client for a "chat" room for the CSCE 463 Project 3/4

 #Client TCP Socket
def client_connection(name, port):
    client_socket = socket.socket() 
    client_socket.connect((name, port))
    client_socket.send(name.encode())
    return client_socket

#client sending
def client_send(socket):
        while True:
            message = socket.recv(1024).decode()
            print("Message recieved from server =", message)
            client_input = input("Send message back to the server:")
            socket.send(client_input.encode())


#information
name = input('Enter Client IP address: ')
port = 8080
client_socket = client_connection(name, port)
client_send(client_socket)





