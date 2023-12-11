import socket
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# Function to safely send messages
def send_encrypted_message(sock, message, cipher):
    encrypted_msg = cipher.encrypt(message)
    sock.sendall(encrypted_msg)

# Create a client socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_host = 'localhost'
server_port = 12345

try:
    client_socket.connect((server_host, server_port))
    print(f"Connected to server: {server_host}:{server_port}")

    # Receive server's public key
    server_public_key = client_socket.recv(2048)
    server_rsa_key = RSA.import_key(server_public_key)

    # Send chosen encryption type to the server
    encryption_type = input("Enter the encryption type (RSA/AES/DES): ")
    client_socket.sendall(encryption_type.encode())

    if encryption_type == 'RSA':
        # Perform RSA encryption
        data = input("Enter data to encrypt: ").encode()
        cipher_rsa = PKCS1_OAEP.new(server_rsa_key)
        encrypted_data = cipher_rsa.encrypt(data)
        client_socket.sendall(encrypted_data)

    elif encryption_type == 'AES':
        # Generate AES key
        aes_key = get_random_bytes(16)

        # Encrypt AES key with server's public RSA key
        cipher_rsa = PKCS1_OAEP.new(server_rsa_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        client_socket.sendall(encrypted_aes_key)

        # Encrypt data with AES
        data = input("Enter data to encrypt: ").encode()
        aes_cipher = AES.new(aes_key, AES.MODE_EAX)
        nonce_and_ciphertext = aes_cipher.nonce + aes_cipher.encrypt(data)
        client_socket.sendall(nonce_and_ciphertext)

    elif encryption_type == 'DES':
        # Generate DES key
        des_key = get_random_bytes(8)

        # Encrypt DES key with server's public RSA key
        cipher_rsa = PKCS1_OAEP.new(server_rsa_key)
        encrypted_des_key = cipher_rsa.encrypt(des_key)
        client_socket.sendall(encrypted_des_key)

        # Encrypt data with DES
        data = input("Enter data to encrypt: ").encode()
        padded_data = pad(data, DES.block_size)
        des_cipher = DES.new(des_key, DES.MODE_ECB)
        encrypted_data = des_cipher.encrypt(padded_data)
        client_socket.sendall(encrypted_data)

except Exception as e:
    print(f"Error: {e}")
finally:
    client_socket.close()
    print("Connection closed.")
