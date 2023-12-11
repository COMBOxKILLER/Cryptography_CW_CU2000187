import socket
import threading
import time
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad

# Function for key rotation
def rotate_keys():
    global rsa_key, public_key, private_key
    while True:
        time.sleep(3600)  # Key rotation every hour
        rsa_key = RSA.generate(2048)
        private_key = rsa_key.export_key()
        public_key = rsa_key.publickey().export_key()
        print("Server keys rotated.")

# Generate initial RSA key pair
rsa_key = RSA.generate(2048)
private_key = rsa_key.export_key()
public_key = rsa_key.publickey().export_key()

# Start key rotation in a separate thread
key_rotation_thread = threading.Thread(target=rotate_keys, daemon=True)
key_rotation_thread.start()

# Create a server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_host = 'localhost'
server_port = 12345
server_socket.bind((server_host, server_port))
server_socket.listen(5)
print(f"Server listening on {server_host}:{server_port}...")

def save_metadata(encryption_type, plaintext, decrypted_data):
    filename = "server_metadata.txt"
    with open(filename, "a") as file:
        file.write(f"Type: {encryption_type}, Plaintext: {plaintext}, Decrypted: {decrypted_data}\n")

def client_connection_handler(client_socket):
    try:
        # Send public key to the client
        client_socket.sendall(public_key)

        # Receive client's chosen encryption type
        encryption_type = client_socket.recv(1024).decode()
        plaintext = None
        decrypted_data = None

        if encryption_type == 'RSA':
            # Handle RSA encrypted data
            encrypted_data = client_socket.recv(2048)
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
            decrypted_data = cipher_rsa.decrypt(encrypted_data)
            plaintext = decrypted_data.decode('utf-8', errors='ignore')

        elif encryption_type == 'AES':
            # Handle AES encrypted data
            encrypted_aes_key = client_socket.recv(2048)
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)
            encrypted_data = client_socket.recv(1024)
            aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=encrypted_data[:16])
            decrypted_data = aes_cipher.decrypt(encrypted_data[16:])
            plaintext = decrypted_data.decode('utf-8', errors='ignore')

        elif encryption_type == 'DES':
            # Handle DES encrypted data
            encrypted_des_key = client_socket.recv(2048)
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
            des_key = cipher_rsa.decrypt(encrypted_des_key)
            encrypted_data = client_socket.recv(1024)
            des_cipher = DES.new(des_key, DES.MODE_ECB)
            decrypted_data = unpad(des_cipher.decrypt(encrypted_data), DES.block_size)
            plaintext = decrypted_data.decode('utf-8', errors='ignore')

        print(f"Decrypted data: {plaintext}")
        save_metadata(encryption_type, plaintext, decrypted_data.hex())

    except Exception as e:
        print(f"Error in connection handler: {e}")
    finally:
        client_socket.close()

while True:
    try:
        # Accept client connection
        client_socket, client_address = server_socket.accept()
        print(f"Connected to client: {client_address}")

        # Handle client connection in a separate thread
        thread = threading.Thread(target=client_connection_handler, args=(client_socket,))
        thread.start()
    except KeyboardInterrupt:
        print("Server shutting down.")
        break

server_socket.close()
