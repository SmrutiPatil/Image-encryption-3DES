import socket
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

bob_private_key = x25519.X25519PrivateKey.generate()
bob_public_key = bob_private_key.public_key()

# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server
server_address = ('localhost', 12345)
client_socket.connect(server_address)

alice_public_key_bytes = None
while True:
    # Send data to the server
    message = bob_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    client_socket.send(message)

    # Receive a response from the server
    alice_public_key_bytes = client_socket.recv(1024)
    if not alice_public_key_bytes:
        break  # If no data is received, break the loop

    break

alice_public_key = x25519.X25519PublicKey.from_public_bytes(alice_public_key_bytes)

# Perform key exchange using the received public key
alice_shared_key = bob_private_key.exchange(alice_public_key)

# Print the shared key as bytes
print('Client shared key (bytes):', alice_shared_key)

# Close the connection
client_socket.close()