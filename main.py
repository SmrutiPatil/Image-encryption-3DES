import argparse
import hashlib
from Des import encrypt, decrypt
from Crypto.Protocol.KDF import PBKDF2
import hmac


salt_const = "fcc124f84b0daaf7dfe85bcd05ce6f3f"


def image_to_binary(image_path):
    with open(image_path, "rb") as image_file:
        image_binary = image_file.read()
    binary_string = "".join(format(byte, "08b") for byte in image_binary)
    return binary_string


def binary_to_image(binary_data, output_path):
    bytes_array = bytearray(
        int(binary_data[i : i + 8], 2) for i in range(0, len(binary_data), 8)
    )
    with open(output_path, "wb") as output_file:
        output_file.write(bytes_array)


def calculate_sha256(data):
    sha256 = hashlib.sha256()
    sha256.update(data.encode("utf-8"))
    return sha256.digest()


def encrypt_image(image_path, password, output_path):
    image_binary = image_to_binary(image_path)
    key = calculate_sha256(password)
    # key = PBKDF2(password, salt_const, dkLen=64, count=1000000, prf=lambda p, s: hmac.new(p, s, hashlib.sha256).digest())
    encrypted_data = encrypt(image_binary, key[:8], len(image_binary))
    binary_to_image(encrypted_data, output_path)
        

def encrypt_image_3Des(image_path, password, output_path):
    image_binary = image_to_binary(image_path)
    # key = calculate_sha256(password)
    key = PBKDF2(password, salt_const, dkLen=64, count=1000000, prf=lambda p, s: hmac.new(p, s, hashlib.sha256).digest())
    print(len(key))
    print(key[:8])
    print(key[8:16])
    print(key[16:24])
    encrypt1 = encrypt(image_binary, key[:9], len(image_binary))
    decrypt1 = decrypt(encrypt1, key[9:17], len(encrypt1))
    encrypted_data = encrypt(decrypt1, key[17:26], len(decrypt1))

    binary_to_image(encrypted_data, output_path)


def decrypt_image(encrypted_image_path, password, output_path):
    encrypted_data = image_to_binary(encrypted_image_path)
    key = calculate_sha256(password)
    # key = PBKDF2(password, salt_const, dkLen=64, count=1000000, prf=lambda p, s: hmac.new(p, s, hashlib.sha256).digest())
    decrypted_data = decrypt(encrypted_data, key[:8], len(encrypted_data))
    binary_to_image(decrypted_data, output_path)


def decrypt_image_3Des(encrypted_image_path, password, output_path):
    encrypted_data = image_to_binary(encrypted_image_path)
    # key = calculate_sha256(password)
    key = PBKDF2(password, salt_const, dkLen=64, count=1000000, prf=lambda p, s: hmac.new(p, s, hashlib.sha256).digest())

    decrypt1 = decrypt(encrypted_data, key[17:26], len(encrypted_data))
    encrypt1 = encrypt(decrypt1, key[9:17], len(decrypt1))
    decrypted_data = decrypt(encrypt1, key[:9], len(encrypt1))
    
    binary_to_image(decrypted_data, output_path)


def main():
    parser = argparse.ArgumentParser(
        description="Image Encryption and Decryption using DES with SHA256 integrity check."
    )
    parser.add_argument("--file", help="Path to the image file", required=True)
    parser.add_argument(
        "--password",
        help="Password to generate the encryption/decryption key",
        required=True,
    )
    parser.add_argument(
        "--to",
        choices=["encrypt", "decrypt"],
        help="Operation mode: 'encrypt' or 'decrypt'",
        required=True,
    )
    args = parser.parse_args()

    if args.to == "encrypt":
        output_path = "encrypted_" + args.file
        encrypt_image(args.file, args.password, output_path)
        print("Image encrypted successfully. Encrypted image saved as:", output_path)
    elif args.to == "decrypt":
        output_path = "decrypted_" + args.file
        decrypt_image(args.file, args.password, output_path)
        print("Image decrypted successfully. Decrypted image saved as:", output_path)


if __name__ == "__main__":
    main()
