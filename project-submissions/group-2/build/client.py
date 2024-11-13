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


def main():
    host = '10.7.23.164'
    port = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))

        # Receive and load the server's public key
        public_key = receive_public_key(client_socket)
        
        while True:
            command = input("Enter command (or 'exit' to quit): ")
            if command.lower() == 'exit':
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

if __name__ == "__main__":
    main()
