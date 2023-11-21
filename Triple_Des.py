pi = 100005

salt_const = "fcc124f84b0daaf7dfe85bcd05ce6f3f"

from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from getpass import getpass
from Crypto.Protocol.KDF import PBKDF2


def encryptor(path, password):
    try:
        with open(path, "rb") as imagefile:
            image = imagefile.read()

        # making multiple of 8
        while len(image) % 8 != 0:
            image += b" "
    except:
        print("Error loading the file")
        exit()

    # SHA256 Hashing
    hash_of_original = SHA256.new(data=image)

    # Password Stuff
    # key_enc = getpass(prompt="Enter min of 8 character long password:")
    key_enc = password

    while len(key_enc) < 8:
        # key_enc = getpass(prompt="Password length < 8 char")
        exit()

    # key_enc_confirm = getpass(prompt="Enter password again:")

    # while key_enc != key_enc_confirm:
    #     # print("Key Mismatch.Try again.")
    #     # key_enc = getpass(prompt="Enter 8 character long password:")

    #     while len(key_enc) < 8:
    #         key_enc = getpass(
    #             prompt="Invalid password! Enter atleast 8 character password:"
    #         )
    #     key_enc_confirm = getpass(prompt="Enter password again:")

    # Hashing Password
    key_enc = PBKDF2(key_enc, salt_const, 48, count=pi)

    # Encrypting
    # print("encrypting...")

    try:
        cipher1 = DES.new(key_enc[0:8], DES.MODE_CBC, key_enc[24:32])
        ciphertext1 = cipher1.encrypt(image)
        cipher2 = DES.new(key_enc[8:16], DES.MODE_CBC, key_enc[32:40])
        ciphertext2 = cipher2.decrypt(ciphertext1)
        cipher3 = DES.new(key_enc[16:24], DES.MODE_CBC, key_enc[40:48])
        ciphertext3 = cipher3.encrypt(ciphertext2)
        # print("ENCRYPTION SUCCESSFUL!!!")
    except:
        # print("Encryption failed...Incorrect Padding/Conversion")
        exit()

    # Concatinating Hash
    ciphertext3 += hash_of_original.digest()

    # Save File OS Stuff
    try:
        dpath = "encrypted_" + path
        with open(dpath, "wb") as image_file:
            image_file.write(ciphertext3)

        # print(f"Encrypted Image Saved successfully as filename {dpath} ")

    except:
        temp_path = input(
            "Saving file failed!.Memory Error/Same name file already exist"
        )
        try:
            dpath = temp_path + path
            dpath = "encrypted_" + path
            with open(dpath, "wb") as image_file:
                image_file.write(ciphertext3)
            # print("Encrypted Image Saved successfully as filename " + dpath)
            exit()
        except:
            # print("Failed....")
            exit()


# Decrypt
def decryptor(encrypted_image_path, password):
    try:
        with open(encrypted_image_path, "rb") as encrypted_file:
            encrypted_data_with_hash = encrypted_file.read()

    except:
        # print("Unable to read source cipher data.")
        exit()

        # Key Input
    # key_dec = getpass(prompt="Enter password:")
    key_dec = password

    # extracting
    extracted_hash = encrypted_data_with_hash[-32:]
    encrypted_data = encrypted_data_with_hash[:-32]

    # Hashing
    key_dec = PBKDF2(key_dec, salt_const, 48, count=pi)

    # decrypting
    # print("Decrypting...")
    try:
        cipher1 = DES.new(key_dec[16:24], DES.MODE_CBC, key_dec[40:48])
        plaintext1 = cipher1.decrypt(encrypted_data)
        cipher2 = DES.new(key_dec[8:16], DES.MODE_CBC, key_dec[32:40])
        plaintext2 = cipher2.encrypt(plaintext1)
        cipher3 = DES.new(key_dec[0:8], DES.MODE_CBC, key_dec[24:32])
        plaintext3 = cipher3.decrypt(plaintext2)

    except:
        # print("Decryption failed...")
        exit()

    # hashing decrypted image
    hash_of_decrypted = SHA256.new(data=plaintext3)

    # Password confirmation
    if hash_of_decrypted.digest() == extracted_hash:
        print("Password Correct !!!")
        print("DECRYPTION SUCCESSFUL!!")
    else:
        print("Incorrect Password!!!")
        exit()

    # saving
    try:
        epath = encrypted_image_path
        if epath[:10] == "encrypted_":
            epath = epath[10:]
        epath = "decrypted_" + epath
        with open(epath, "wb") as image_file:
            image_file.write(plaintext3)
        print("Image saved successully with name " + epath)
    except:
        temp_path = input("Saving file failed!")
        try:
            epath = temp_path + encrypted_image_path
            with open(epath, "wb") as image_file:
                image_file.write(plaintext3)
            print("Image saved" + epath)
        except:
            print("failed Exiting...")
            exit()


# print("Image Encryption using Triple-Des")
# print("")

# print("Provide an 8 Digit Long Password")

# print("Encryption ")
# print("Encrypting file size depends on the Ram and storage of the CPU")
# print("")
# print("")


# # Menu Driven Approach
# try:
#     choice = int(input("		Press 1 for Encryption || 2 for Decryption: "))
#     while choice != 1 and choice != 2:
#         choice = int(input("		      Invalid Choice! Try Again:"))
# except:
#     print("Error, please provide valid Input")
#     exit()


# if choice == 1:
#     # Encryption
#     path = input("Enter image's name to be encypted:")
#     encryptor(path)

# else:
#     # Decryption
#     encrypted_image_path = input("Enter file name to decrypted:")
#     decryptor(encrypted_image_path)

# print("")
# print("")
