import socket
import threading
import os
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

## This Program acts as the Server for a "chat" room for the CSCE 463 Project 3/4
# Setting up the chat room
chat_socket = socket.socket()
chat_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
host_name = socket.gethostname()
s_ip = socket.gethostbyname(host_name)
port = 8080
chat_socket.bind((host_name, port))

# connectionlist stores dicts: {'conn': socket, 'pubkey': RSA.RsaKey, 'name': str}
connectionlist = []

# Paths for server keys
SERVER_PRIV = 'server_private.pem'
SERVER_PUB = 'server_public.pem'


def generate_rsa_keypair(priv_path, pub_path, bits=2048):
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        return
    key = RSA.generate(bits)
    with open(priv_path, 'wb') as f:
        f.write(key.export_key())
    with open(pub_path, 'wb') as f:
        f.write(key.publickey().export_key())


def load_private_key(path):
    with open(path, 'rb') as f:
        return RSA.import_key(f.read())


def load_public_key(pem_bytes):
    return RSA.import_key(pem_bytes)


def recv_all(conn, n):
    data = b''
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


def recv_frame(conn):
    # Read total length prefix
    raw_len = recv_all(conn, 4)
    if not raw_len:
        return None
    total_len = struct.unpack('!I', raw_len)[0]
    payload = recv_all(conn, total_len)
    if not payload:
        return None
    # first 16 bytes are four 4-byte lengths
    if len(payload) < 16:
        return None
    l1, l2, l3, l4 = struct.unpack('!IIII', payload[:16])
    idx = 16
    enc_sess = payload[idx:idx + l1]; idx += l1
    nonce = payload[idx:idx + l2]; idx += l2
    tag = payload[idx:idx + l3]; idx += l3
    ciphertext = payload[idx:idx + l4]
    return enc_sess, nonce, tag, ciphertext


def decrypt_frame(enc_sess, nonce, tag, ciphertext, private_key):
    # decrypt AES key with server private RSA key
    rsa_cipher = PKCS1_OAEP.new(private_key)
    aes_key = rsa_cipher.decrypt(enc_sess)
    # decrypt AES-GCM
    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes_cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


def build_frame_for_pubkey(plaintext_bytes, recipient_pubkey):
    # generate AES key
    aes_key = get_random_bytes(32)  # AES-256
    aes_cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext_bytes)
    nonce = aes_cipher.nonce
    # encrypt AES key with recipient RSA pubkey
    rsa_cipher = PKCS1_OAEP.new(recipient_pubkey)
    enc_sess = rsa_cipher.encrypt(aes_key)
    header = struct.pack('!IIII', len(enc_sess), len(nonce), len(tag), len(ciphertext))
    payload = header + enc_sess + nonce + tag + ciphertext
    frame = struct.pack('!I', len(payload)) + payload
    return frame


def receive_messages(connection, client_name, client_priv=None):
    """Continuously listens for incoming frames from the client, decrypts,
    and rebroadcasts to other clients encrypted for each recipient.
    """
    try:
        server_priv = load_private_key(SERVER_PRIV)
        while True:
            parts = recv_frame(connection)
            if not parts:
                break
            enc_sess, nonce, tag, ciphertext = parts
            try:
                plaintext = decrypt_frame(enc_sess, nonce, tag, ciphertext, server_priv)
            except Exception as e:
                print('Failed to decrypt message from', client_name, e)
                continue
            # plaintext format: 4-byte signature length || signature || message
            if len(plaintext) < 4:
                print('Malformed plaintext from', client_name)
                continue
            sig_len = struct.unpack('!I', plaintext[:4])[0]
            if len(plaintext) < 4 + sig_len:
                print('Incomplete signature from', client_name)
                continue
            signature = plaintext[4:4 + sig_len]
            message = plaintext[4 + sig_len:]

            # find sender public key from connectionlist
            sender_pub = None
            for cinfo in connectionlist:
                if cinfo['conn'] == connection:
                    sender_pub = cinfo.get('pubkey')
                    break
            if sender_pub is None:
                print('Sender public key not found for', client_name)
                continue

            # verify client signature
            try:
                pkcs1_15.new(sender_pub).verify(SHA256.new(message), signature)
            except (ValueError, TypeError) as e:
                print('Signature verification failed for', client_name, e)
                continue

            # Log the verified message (decoded)
            try:
                print(message.decode())
            except Exception:
                print('Received non-text message from', client_name)

            # Sign the message with server private key before broadcasting
            server_sig = pkcs1_15.new(server_priv).sign(SHA256.new(message))
            broadcast_plain = struct.pack('!I', len(server_sig)) + server_sig + message

            for cinfo in connectionlist:
                if cinfo['conn'] != connection:
                    try:
                        frame = build_frame_for_pubkey(broadcast_plain, cinfo['pubkey'])
                        cinfo['conn'].sendall(frame)
                    except Exception as e:
                        print('Failed to forward to', cinfo.get('name'), e)
    except Exception as e:
        print("Connection lost:", e)



# this isn't needed for the time being, a server isn't "sending" messages, they are relaying back to the clients
        
#def send_messages(connection, server_name, client_name):
    #"""Continuously waits for server operator input and sends it to the client."""
    #try:
        #while True:
            #my_input = input(f"{server_name}: ")
            #connection.send(f"{server_name}: {my_input}\r\n".encode())
   # except Exception as e:
        #print("An error has occured:", e)
    print('Connection lost:', e)

def talk_with_client(connection, address):
    try:
        print("Recieved connection from", address[0])


        # Exchange names
        client_name = connection.recv(1024).decode().strip()
        print(client_name, 'has connected.')
        server_name = s_ip
        connection.send(server_name.encode())

        # receive client's public key (length-prefixed)
        raw = recv_all(connection, 4)
        if not raw:
            print('No public key length from client')
            connection.close()
            return
        pub_len = struct.unpack('!I', raw)[0]
        pub_pem = recv_all(connection, pub_len)
        if not pub_pem:
            print('Failed to receive client public key')
            connection.close()
            return
        client_pubkey = load_public_key(pub_pem)

        # store connection info
        connectionlist.append({'conn': connection, 'pubkey': client_pubkey, 'name': client_name})

        # Spin up one thread for receiving
        recv_thread = threading.Thread(target=receive_messages, args=(connection, client_name))
        #send_thread = threading.Thread(target=send_messages, args=(connection, server_name, client_name))
        recv_thread.daemon = True
        #send_thread.daemon = True
        recv_thread.start()
        #send_thread.start()

        # Keep this thread alive while the two above run
        recv_thread.join()

    except Exception as e:
        print("An error has occured:", e)


if __name__ == '__main__':
    try:
        # Ensure server RSA keys exist
        generate_rsa_keypair(SERVER_PRIV, SERVER_PUB)

        print('Welcome to Chat\n')
        print('Binding was successfull!')
        print('Your IP =', s_ip)
        print('Chat log:')
        chat_socket.listen(5)

        while True:
            connection, add = chat_socket.accept()
            new_connection = threading.Thread(target=talk_with_client, args=(connection, add))
            new_connection.start()

    except Exception as e:
        print("An error has occured:", e)


def DoNothing():
    return 0