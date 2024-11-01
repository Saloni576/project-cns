import socket
import subprocess
import threading

MAX_CLIENTS = 5  # Limit to control maximum simultaneous client connections
client_semaphore = threading.Semaphore(MAX_CLIENTS)

def handle_client(conn, addr):
    print(f"Connected by {addr}")
    with conn:
        while True:
            try:
                command = conn.recv(1024).decode()
                if not command or command.lower() == 'exit':
                    print(f"Client {addr} disconnected")
                    break
                
                print(f"Received command from {addr}: {command}")
                try:
                    # Execute the command and capture the output
                    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                    response = output.decode()
                except subprocess.CalledProcessError as e:
                    response = e.output.decode()

                conn.sendall(response.encode())
            except ConnectionResetError:
                print(f"Connection with {addr} was reset by the client.")
                break  # Handle abrupt client disconnection
    print(f"Connection with {addr} closed")
    client_semaphore.release()  # Release semaphore after disconnecting

def main():
    host = '10.7.23.164'  # Localhost
    port = 12345          # Port to listen on

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Server listening on {host}:{port}")

        while True:
            client_semaphore.acquire()  # Allow up to MAX_CLIENTS simultaneous connections
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

if __name__ == "__main__":
    main()
