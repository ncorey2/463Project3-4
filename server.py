import socket
import threading

## This Program acts as the Server for a "chat" room for the CSCE 463 Project 3/4

#setting up the chat room
chat_socket = socket.socket()
chat_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
host_name = socket.gethostname()
s_ip = socket.gethostbyname(host_name)
port = 8080
chat_socket.bind((host_name, port))


def talk_with_client(connection, address):
            try:
                print("Recieved connection from", address[0])
                print(connection.recv(1024).decode() + ' has connected.')
                while True:
                    my_input = input("Send message:")
                    if("Recieved" not in my_input):
                        connection.send(my_input.encode())
                        result = connection.recv(1024).decode()
                        print("Result equals:", result)
            except Exception as e:
                print("An error has occured:", e)
        

try:
    print("Welcome to Chat\n")

    print("Binding was successfull!")
    print("Your IP = ", s_ip)
    chat_socket.listen(5)

    #While loop so the chat room will keep making threads for new acceptances
    while True:
        connection, add = chat_socket.accept()
        new_connection = threading.Thread(target=talk_with_client, args= (connection, add))
        new_connection.start()

except Exception as e:
    print("An error has occured:", e)



   




