import socket
import threading
import os
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

"""
This Program acts as the Server for a chat room for the CSCE 463 Project 3/4
@authors Noah Corey, Grant Mielak, Maya Wilson
@date 4/15/2026
"""

# Setting up the chat room
chat_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
chat_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
host_name = socket.gethostname()
s_ip = socket.gethostbyname(host_name)
port = 8080
chat_socket.bind(('', port))

# connectionlist stores dicts: {'conn': socket, 'pubkey': RSA.RsaKey, 'name': str}
# connectionlist is used to store all incoming connections to the server
connectionlist = []

# Paths for server keys
SERVER_PRIV = 'server_private.pem'
SERVER_PUB = 'server_public.pem'


"""
Generates a public and private key for the server using the RSA library if no public and private key already exists
"""
def generate_rsa_keypair(priv_path, pub_path, bits=2048):
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        return
    key = RSA.generate(bits)
    with open(priv_path, 'wb') as f:
        f.write(key.export_key())
    with open(pub_path, 'wb') as f:
        f.write(key.publickey().export_key())


"""
Loads the server's private key
"""
def load_private_key(path):
    with open(path, 'rb') as f:
        return RSA.import_key(f.read())

"""
Loads the server's public key
"""
def load_public_key(pem_bytes):
    return RSA.import_key(pem_bytes)


"""
Recieves all incoming data from a client
"""
def recv_all(conn, n):
    data = b''
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


"""
Splits the recieved data from a client into the enc_sess, nonce, tag, and ciphertext
"""
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


"""
decrypts recieved data from a client
"""
def decrypt_frame(enc_sess, nonce, tag, ciphertext, private_key):
    # decrypt AES key with server private RSA key
    rsa_cipher = PKCS1_OAEP.new(private_key)
    aes_key = rsa_cipher.decrypt(enc_sess)
    # decrypt AES-GCM
    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes_cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

"""
 encrypts data with the recipients public key 
"""
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


"""
Continuously listens for incoming frames from the client, decrypts,
 and rebroadcasts to other clients encrypted for each recipient.
"""
def receive_messages(connection, client_name, client_priv=None):
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
                # only sends messages to clients who are not the sender
                if cinfo['conn'] != connection:
                    try:
                        frame = build_frame_for_pubkey(broadcast_plain, cinfo['pubkey'])
                        cinfo['conn'].sendall(frame)
                    except Exception as e:
                        print('Failed to forward to', cinfo.get('name'), e)
    except Exception as e:
        print("Connection lost:", e)
    finally:
        # Remove this connection from the global list and close the socket
        connectionlist[:] = [c for c in connectionlist if c['conn'] != connection]
        try:
            connection.close()
        except Exception:
            pass


"""
Sets up a connection with a client by recieving their public key, then storing their connection information
and finally setting up a new thread which listens for incoming data from the client
"""
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
        recv_thread.daemon = True
        recv_thread.start()

        # Keep this thread alive while the two above run
        recv_thread.join()

    except Exception as e:
        print("An error has occured:", e)


if __name__ == '__main__':
    try:
        # Ensure server RSA keys exist
        generate_rsa_keypair(SERVER_PRIV, SERVER_PUB)

        #Introduction to chat
        print('Welcome to Chat\n')
        print('Binding was successfull!')
        print('Your IP =', s_ip)
        print('Chat log:')
        chat_socket.listen(5)

        #Continously look for clients attempting to connect to the server
        while True:
            connection, add = chat_socket.accept()
            new_connection = threading.Thread(target=talk_with_client, args=(connection, add))
            new_connection.start()

    except Exception as e:
        print("An error has occured:", e)
