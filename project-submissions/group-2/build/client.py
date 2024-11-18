import sys
import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_keys():
    """Generate RSA key pair for the client."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Save keys to files
    with open("client_private_key.pem", "wb") as priv_key_file:
        priv_key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open("client_public_key.pem", "wb") as pub_key_file:
        pub_key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print("Client keys generated.")
    return private_key, public_key

def receive_public_key(conn):
    """Receive server's public key."""
    key_length = int.from_bytes(conn.recv(4), 'big')
    public_key_data = conn.recv(key_length)

    with open("server_public_key.pem", "wb") as pub_key_file:
        pub_key_file.write(public_key_data)

    public_key = serialization.load_pem_public_key(public_key_data)
    print("Server's public key received and loaded.")
    return public_key

def send_public_key(conn, public_key):
    """Send the client's public key to the server."""
    public_key_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.sendall(len(public_key_data).to_bytes(4, 'big'))
    conn.sendall(public_key_data)
    print("Client's public key sent to server.")

def is_valid_ip(ip):
    """Validate IPv4 address format."""
    parts = ip.split('.')
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

def is_valid_port(port):
    """Validate port number."""
    return port.isdigit() and 1 <= int(port) <= 65535

def main():
    host = '127.0.0.1'
    port = 12345

    if len(sys.argv) >= 2:
        if is_valid_ip(sys.argv[1]):
            host = sys.argv[1]
        else:
            print("Error: Invalid IP address format.")
            sys.exit(1)
    if len(sys.argv) == 3:
        if is_valid_port(sys.argv[2]):
            port = int(sys.argv[2])
        else:
            print("Error: Invalid port number.")
            sys.exit(1)
    elif len(sys.argv) > 3:
        print("Usage: python3 client.py [<ip> <port>]")
        sys.exit(1)

    try:
        private_key, public_key = generate_keys()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((host, port))

            send_public_key(client_socket, public_key)
            server_public_key = receive_public_key(client_socket)

            while True:
                try:
                    command = input("Enter command (or 'exit' to quit): ")
                    if command.lower() == 'exit':
                        print("Disconnecting from the server...")
                        break
                    
                    encrypted_command = server_public_key.encrypt(
                        command.encode(),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    client_socket.sendall(encrypted_command)

                    response = client_socket.recv(4096)
                    decrypted_response = private_key.decrypt(
                        response,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    print("Response from server:")
                    print(decrypted_response.decode())
                except KeyboardInterrupt:
                    print("\nClient disconnected gracefully.")
                    break
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
