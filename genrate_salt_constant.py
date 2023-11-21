import secrets

# Generate a new random 16-byte (128-bit) salt constant
new_salt_constant = secrets.token_bytes(16).hex()

# Print or use the generated new salt constant
print("New Salt Constant:", new_salt_constant)