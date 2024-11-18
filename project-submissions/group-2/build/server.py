import os
import sys
import shlex
import socket
import threading
import subprocess
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import re

MAX_CLIENTS = 5
client_semaphore = threading.Semaphore(MAX_CLIENTS)
client_keys = {}

def generate_keys():
    """Generate RSA key pair for the server."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    with open("server_private_key.pem", "wb") as priv_key_file:
        priv_key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open("server_public_key.pem", "wb") as pub_key_file:
        pub_key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    print("Server keys generated.")
    return private_key, public_key

if not os.path.exists("server_private_key.pem"):
    server_private_key, server_public_key = generate_keys()
else:
    with open("server_private_key.pem", "rb") as key_file:
        server_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    with open("server_public_key.pem", "rb") as key_file:
        server_public_key = serialization.load_pem_public_key(key_file.read())

def send_public_key(conn):
    """Send the server's public key to the client."""
    with open("server_public_key.pem", "rb") as pub_key_file:
        public_key_data = pub_key_file.read()
    conn.sendall(len(public_key_data).to_bytes(4, 'big'))
    conn.sendall(public_key_data)
    print("Server's public key sent to client.")

def receive_public_key(conn, addr):
    """Receive the client's public key."""
    key_length = int.from_bytes(conn.recv(4), 'big')
    public_key_data = conn.recv(key_length)

    client_key_file = f"client_{addr[1]}_public_key.pem"
    with open(client_key_file, "wb") as pub_key_file:
        pub_key_file.write(public_key_data)

    client_public_key = serialization.load_pem_public_key(public_key_data)
    client_keys[addr[1]] = client_public_key
    print(f"Client's public key from {addr} received and saved.")
    return client_public_key

def execute_command(command):
    """Execute a command and return the output."""
    parts = shlex.split(command)
    base_command = parts[0] if parts else ""
    if base_command in ["./setup", "./logappend", "./logread"]:
        try:
            output = subprocess.check_output(parts, stderr=subprocess.STDOUT)
            return output.decode()
        except subprocess.CalledProcessError as e:
            return e.output.decode()
    else:
        return "Error: Command not allowed."

def valid_ip(ip):
    """Validate if the given string is a valid IP address."""
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return bool(re.match(pattern, ip))

def valid_port(port):
    """Validate if the given port is within the allowed range."""
    return port.isdigit() and 1024 <= int(port) <= 65535

def handle_client(conn, addr):
    """Handle communication with the client."""
    print(f"Connected by {addr}")
    with conn:
        client_public_key = receive_public_key(conn, addr)
        send_public_key(conn)

        while True:
            try:
                encrypted_command = conn.recv(256)
                if not encrypted_command:
                    print(f"Client {addr} disconnected.")
                    break

                command = server_private_key.decrypt(
                    encrypted_command,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).decode()
                print(f"Received command from {addr}")

                if command.lower() == 'exit':
                    break

                response = execute_command(command)

                encrypted_response = client_public_key.encrypt(
                    response.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                conn.sendall(encrypted_response)
            except ConnectionResetError:
                print(f"Connection with {addr} was reset.")
                break

    print(f"Connection with {addr} closed.")
    client_semaphore.release()

def main():
    """Main function to start the server."""
    host = '127.0.0.1'
    port = 12345

    if len(sys.argv) >= 2 and valid_ip(sys.argv[1]):
        host = sys.argv[1]
    if len(sys.argv) == 3 and valid_port(sys.argv[2]):
        port = int(sys.argv[2])

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((host, port))
            server_socket.listen()
            print(f"Server listening on {host}:{port}")

            while True:
                client_semaphore.acquire()
                conn, addr = server_socket.accept()
                threading.Thread(target=handle_client, args=(conn, addr)).start()
    except KeyboardInterrupt:
        print("\nServer shut down gracefully.")

if __name__ == "__main__":
    main()
