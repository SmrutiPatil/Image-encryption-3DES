import socket
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

alice_private_key = x25519.X25519PrivateKey.generate()
alice_public_key = alice_private_key.public_key()

# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to a specific address and port
server_address = ("localhost", 12345)
server_socket.bind(server_address)

# Listen for incoming connections (maximum of 1 connection in this example)
server_socket.listen(1)

print("Server listening on {}:{}".format(*server_address))

# Accept a connection
client_socket, client_address = server_socket.accept()
print("Connection from", client_address)
bob_public_key = None

while True:
    # Receive data from the client
    bob_public_key_bytes = client_socket.recv(1024)
    if not bob_public_key_bytes:
        break  # If no data is received, break the loop

    # Convert the received bytes to a public key object
    bob_public_key = x25519.X25519PublicKey.from_public_bytes(bob_public_key_bytes)
    print("Received public key:", bob_public_key)

    # Perform key exchange and send the shared key back to the client
    shared_key = alice_private_key.exchange(bob_public_key)
    print("Shared key (bytes):", shared_key)

    with open('alice-shared-key.txt','wb') as file:
        file.write(shared_key)

    # Send the bytes directly without conversion
    message = alice_public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    client_socket.send(message)

    break

# Close the connection
client_socket.close()
server_socket.close()
