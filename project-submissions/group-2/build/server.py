import socket
import subprocess
import threading
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

MAX_CLIENTS = 5
client_semaphore = threading.Semaphore(MAX_CLIENTS)

# Function to generate RSA key pair
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Save private key to a file
    with open("private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save public key to a file
    public_key = private_key.public_key()
    with open("public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    print("RSA key pair generated.")

    return private_key, public_key

# Generate or load RSA keys
if not (os.path.exists("private_key.pem") and os.path.exists("public_key.pem")):
    private_key, _ = generate_keys()  # Call generate_keys() if keys do not exist
    print("Generated new RSA key pair.")
else:
    # Load the private key if it already exists
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    print("Loaded existing RSA key pair from files.")


# Send the public key to the client
def send_public_key(conn):
    with open("public_key.pem", "rb") as pub_key_file:
        public_key_data = pub_key_file.read()
    conn.sendall(len(public_key_data).to_bytes(4, 'big'))  # Send the length first
    conn.sendall(public_key_data)  # Then send the actual file content

def handle_client(conn, addr):
    print(f"Connected by {addr}")
    with conn:
        # Send the public key file to the client
        send_public_key(conn)
        
        while True:
            try:
                # Receive and decrypt the command
                encrypted_command = conn.recv(256)
                if not encrypted_command:
                    print(f"Client {addr} disconnected")
                    break

                command = private_key.decrypt(
                    encrypted_command,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).decode()
                print(f"Received command from {addr}: {command}")
                
                if command.lower() == 'exit':
                    break

                # Execute the command and capture the output
                try:
                    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                    response = output.decode()
                except subprocess.CalledProcessError as e:
                    response = e.output.decode()

                # Send the response unencrypted
                conn.sendall(response.encode())
            except ConnectionResetError:
                print(f"Connection with {addr} was reset by the client.")
                break
    print(f"Connection with {addr} closed")
    client_semaphore.release()

def main():
    host = '10.7.23.164'
    port = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Server listening on {host}:{port}")

        while True:
            client_semaphore.acquire()
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

if __name__ == "__main__":
    main()
