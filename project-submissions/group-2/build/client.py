import sys
import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

def receive_public_key(conn):
    # Receive the length of the public key file first (4 bytes)
    key_length = int.from_bytes(conn.recv(4), 'big')
    public_key_data = conn.recv(key_length)

    # Write the public key to a file
    with open("public_key.pem", "wb") as pub_key_file:
        pub_key_file.write(public_key_data)

    # Load the public key for encryption
    public_key = serialization.load_pem_public_key(public_key_data)

    # Print confirmation message
    print("Public key received from server and loaded successfully.")

    return public_key

def is_valid_ip(ip):
    """Validate IPv4 address format."""
    parts = ip.split('.')
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

def is_valid_port(port):
    """Validate port number."""
    return port.isdigit() and 1 <= int(port) <= 65535

def main():
    # Default IP and port
    host = '127.0.0.1'
    port = 12345

    # Parse command-line arguments for IP and port
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
            print("Error: Invalid port number. Must be an integer between 1 and 65535.")
            sys.exit(1)
    elif len(sys.argv) > 3:
        print("Usage: python3 client.py [<ip> <port>]")
        sys.exit(1)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((host, port))

            # Receive and load the server's public key
            public_key = receive_public_key(client_socket)
            
            while True:
                try:
                    command = input("Enter command (or 'exit' to quit): ")
                    if command.lower() == 'exit':
                        print("Disconnecting from the server...")
                        break
                    
                    # Encrypt the command with the server's public key
                    encrypted_command = public_key.encrypt(
                        command.encode(),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    client_socket.sendall(encrypted_command)

                    # Receive the server's response (unencrypted)
                    response = client_socket.recv(4096).decode()
                    print("Response from server:")
                    print(response)
                except KeyboardInterrupt:
                    print("\nClient disconnected gracefully.")
                    break

    except KeyboardInterrupt:
        print("\nClient disconnected gracefully.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
