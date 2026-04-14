import socket
import threading
import os
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

## This Program acts as the Client for a "chat" room for the CSCE 463 Project 3/4

# Paths for server key (client paths will be per-name)
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


def load_public_key_path(path):
    with open(path, 'rb') as f:
        return RSA.import_key(f.read())


def recv_all(conn, n):
    data = b''
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


def recv_frame(conn):
    raw_len = recv_all(conn, 4)
    if not raw_len:
        return None
    total_len = struct.unpack('!I', raw_len)[0]
    payload = recv_all(conn, total_len)
    if not payload:
        return None
    l1, l2, l3, l4 = struct.unpack('!IIII', payload[:16])
    idx = 16
    enc_sess = payload[idx:idx + l1]; idx += l1
    nonce = payload[idx:idx + l2]; idx += l2
    tag = payload[idx:idx + l3]; idx += l3
    ciphertext = payload[idx:idx + l4]
    return enc_sess, nonce, tag, ciphertext


def decrypt_frame(enc_sess, nonce, tag, ciphertext, private_key):
    rsa_cipher = PKCS1_OAEP.new(private_key)
    aes_key = rsa_cipher.decrypt(enc_sess)
    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes_cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


def build_frame_for_pubkey(plaintext_bytes, recipient_pubkey):
    aes_key = get_random_bytes(32)
    aes_cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext_bytes)
    nonce = aes_cipher.nonce
    rsa_cipher = PKCS1_OAEP.new(recipient_pubkey)
    enc_sess = rsa_cipher.encrypt(aes_key)
    header = struct.pack('!IIII', len(enc_sess), len(nonce), len(tag), len(ciphertext))
    payload = header + enc_sess + nonce + tag + ciphertext
    frame = struct.pack('!I', len(payload)) + payload
    return frame


def client_connection(name, port):
    client_socket = socket.socket()
    client_socket.connect((name, port))
    return client_socket


def receive_messages(sock, client_name, client_priv, server_pub):
    """Continuously listens for incoming messages from the server, verifies server signature, and displays."""
    try:
        while True:
            parts = recv_frame(sock)
            if not parts:
                break
            enc_sess, nonce, tag, ciphertext = parts
            try:
                plaintext = decrypt_frame(enc_sess, nonce, tag, ciphertext, client_priv)
            except Exception as e:
                print('Failed to decrypt incoming message', e)
                continue

            # plaintext format: 4-byte signature length || signature || message
            if len(plaintext) < 4:
                print('Malformed incoming frame')
                continue
            sig_len = struct.unpack('!I', plaintext[:4])[0]
            if len(plaintext) < 4 + sig_len:
                print('Incomplete signature in incoming frame')
                continue
            signature = plaintext[4:4 + sig_len]
            message = plaintext[4 + sig_len:]

            # Verify server signature if we have server public key
            if server_pub is not None:
                try:
                    pkcs1_15.new(server_pub).verify(SHA256.new(message), signature)
                except (ValueError, TypeError) as e:
                    print('Server signature verification failed', e)
                    continue

            try:
                print(f"\r{message.decode()}", flush=True)
                print(f"\r{client_name}: ", end="", flush=True)
            except Exception:
                print('Received non-text message')
    except Exception as e:
        print("Connection lost:", e)


def send_messages(sock, client_name, server_pub, client_priv):
    """Continuously waits for user input, encrypts with server pubkey, and sends it."""
    try:
        while True:
            client_input = input(f"{client_name}: ")
            msg = f"{client_name}: {client_input}".encode()
            # Sign the message with client's private key (client_priv is loaded in client_send and passed via closure)
            # Note: send_messages is invoked only when server_pub is present and client private key exists
            try:
                signature = pkcs1_15.new(client_priv).sign(SHA256.new(msg))
                signed_plain = struct.pack('!I', len(signature)) + signature + msg
            except Exception:
                # fallback: send unsigned message (not recommended)
                signed_plain = msg

            frame = build_frame_for_pubkey(signed_plain, server_pub)
            sock.sendall(frame)
    except Exception as e:
        print('An error has occured:', e)


def client_send(sock, client_name):
    # ensure keys (per-client files named by client_name)
    priv_path = f'client_private_{client_name}.pem'
    pub_path = f'client_public_{client_name}.pem'
    generate_rsa_keypair(priv_path, pub_path)
    client_priv = load_private_key(priv_path)
    # send name
    sock.send(client_name.encode())
    # receive server name
    server_name = sock.recv(1024).decode()
    print(f"Connected to server: {server_name}")
    # send client public key (length-prefixed)
    with open(pub_path, 'rb') as f:
        pubpem = f.read()
    sock.sendall(struct.pack('!I', len(pubpem)))
    sock.sendall(pubpem)

    # load server public key
    if not os.path.exists(SERVER_PUB):
        print('Warning: server public key not found locally (server_public.pem). Ensure server_public.pem is present to encrypt messages to server.')
        server_pub = None
    else:
        server_pub = load_public_key_path(SERVER_PUB)

    print('You can now send messages freely.\n')

    # Spin up one thread for receiving, one for sending
    recv_thread = threading.Thread(target=receive_messages, args=(sock, client_name, client_priv, server_pub))
    recv_thread.daemon = True
    recv_thread.start()

    if server_pub is None:
        print('Cannot send encrypted messages without server public key.')
    else:
        send_messages(sock, client_name, server_pub, client_priv)


# Information
name = input('Enter Server IP address: ')
client_name = input('Enter your name: ')
port = 8080
client_socket = client_connection(name, port)
client_send(client_socket, client_name)