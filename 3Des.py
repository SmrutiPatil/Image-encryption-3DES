from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from getpass import getpass
from Des import encrypt, decrypt
from PIL import Image
from io import BytesIO

pi = 100005
salt_const = b"fcc124f84b0daaf7dfe85bcd05ce6f3f"


def view_decrypted_image(image_bytes):
    # Create a BytesIO object to work with the image data
    image_io = BytesIO(image_bytes)
    print("Iamhere")
    # Open the image using PIL
    image = Image.open(image_io)

    # Display the image
    image.show()
    # Save the image as a PNG file

    image.save("output.png")


# encrypting function
def encryptor(path):
    # opening the image file
    try:
        with open(path, "rb") as imagefile:
            image = imagefile.read()

        # padding
        while len(image) % 8 != 0:
            image += b" "
    except:
        print(
            "Error loading the file, make sure file is in same directory, spelled correctly and non-corrupted"
        )
        exit()

    length = len(image)
    dpath = "length_" + path.replace(".png", ".txt")
    with open(dpath, "w") as length_file:
        length_file.write(str(length))

    print(length)

    # hashing original image in SHA256
    hash_of_original = SHA256.new(data=image)

    image_int = int.from_bytes(image, byteorder="big")

    # Convert integer to binary string
    image_bin = bin(image_int)[2:]
    print(image_bin)
    # print(image_bin)
    # print(type(image_bin))

    # Inputting Keys
    key_enc = getpass(prompt="		      Enter minimum 8 character long password:")
    # Checking if key is of invalid length
    while len(key_enc) < 8:
        key_enc = getpass(
            prompt="		      Invalid password! Enter atleast 8 character password:"
        )

    key_enc_confirm = getpass(prompt="		       Enter password again:")
    while key_enc != key_enc_confirm:
        print("Key Mismatch.Try again.")
        key_enc = getpass(prompt="		      Enter 8 character long password:")

        # Checking if key is of invalid length
        while len(key_enc) < 8:
            key_enc = getpass(
                prompt="		      Invalid password! Enter atleast 8 character password:"
            )
        key_enc_confirm = getpass(prompt="		       Enter password again:")

    # Salting and hashing password
    key_enc = PBKDF2(key_enc, salt_const, 24, count=pi)
    print(key_enc[:8])

    # Encrypting using triple 3 key DES
    print("			encrypting...")
    try:
        encrypted_image_string = encrypt(image_bin, key_enc[:8], length)
        encrypted_image = bytes(encrypted_image_string, "utf-8")

        print("			!!!ENCRYPTION SUCCESSFUL!!!")
    except:
        print(
            "			Encryption failed...Possible causes:Library not installed properly/low device memory/Incorrect padding or conversions"
        )
        exit()
    # print(hash_of_original.digest())
    # print(len(encrypted_image))

    encrypted_image += hash_of_original.digest()

    print(encrypted_image)
    print(len(encrypted_image))

    # print(encrypted_image[-32:])

    # Saving the file encrypted
    try:
        dpath = "encrypted_" + path
        with open(dpath, "wb") as image_file:
            image_file.write(encrypted_image)
        print("			Encrypted Image Saved successfully as filename " + dpath)

    except:
        temp_path = input(
            "			Saving file failed!. Enter alternate name without format to save the encrypted file. If it is still failing then check system memory"
        )
        try:
            dpath = temp_path + path
            dpath = "encrypted_" + path
            with open(dpath, "wb") as image_file:
                image_file.write(encrypted_image)
            print("	  		Encrypted Image Saved successfully as filename " + dpath)
            exit()
        except:
            print("			Failed....Exiting...")
            exit()


def decryptor(encrypted_image_path):
    try:
        with open(encrypted_image_path, "rb") as encrypted_file:
            encrypted_data_with_hash = encrypted_file.read()
            # print(type(encrypted_data_with_hash))
            # print(encrypted_data_with_hash)

    except:
        print(
            "			Unable to read source cipher data. Make sure the file is in same directory...Exiting..."
        )
        exit()

    # Inputting the key
    key_dec = getpass(prompt="		      Enter password:")

    length_filename = encrypted_image_path.replace("encrypted_", "length_").replace(
        ".png", ".txt"
    )
    with open(length_filename, "r") as length_file:
        length = int(length_file.read())

    # extracting hash and cipher data without hash
    extracted_hash = encrypted_data_with_hash[-32:]
    encrypted_data = encrypted_data_with_hash[:-32]
    print(len(extracted_hash))
    # print(encrypted_data)
    print(len(encrypted_data))

    while len(encrypted_data) % 8 != 0:
        encrypted_data += b" "

    # print(type(encrypted_data))
    encrypted_data_int = int.from_bytes(encrypted_data, byteorder="big")

    # Convert integer to binary string
    encrypted_data_bin = bin(encrypted_data_int)[2:]
    encrypted_data_bin += "00"
    # print(encrypted_data_bin)
    print(len(encrypted_data_bin))
    # print(type(encrypted_data_bin))
    # print(len(encrypted_data_bin))

    # salting and hashing password
    key_dec = PBKDF2(key_dec, salt_const, 24, count=pi)
    print(key_dec[:8])

    # decrypting using triple 3 key DES
    print("			Decrypting...")
    # try:
    # print(encrypted_data_bin)
    print("Working......")
    print(length)
    decrypted_image_string = decrypt(encrypted_data_bin, key_dec[:8], length)
    decrypted_image = bytes(decrypted_image_string, "utf-8")
    # view_decrypted_image(b"\x89PNG\r\n" + decrypted_image)

    # except:
    #     print(
    #         "			Decryption failed...Possible causes:Library not installed properly/low device memory/Incorrect padding or conversions"
    #     )
    #     exit()

    print("            Hashing......")
    # hashing decrypted plain text
    hash_of_decrypted = SHA256.new(data=decrypted_image)
    print(hash_of_decrypted.digest())
    print(extracted_hash)

    # matching hashes
    if hash_of_decrypted.digest() == extracted_hash:
        print("Password Correct !!!")
        print("			DECRYPTION SUCCESSFUL!!!")
    else:
        print("Incorrect Password!!!")
        exit()

    # saving the decrypted file
    try:
        epath = encrypted_image_path
        if epath[:10] == "encrypted_":
            epath = epath[10:]
        epath = "decrypted_" + epath
        with open(epath, "wb") as image_file:
            image_file.write(decrypted_image)
        print("			Image saved successully with name " + epath)
        print(
            "			Note: If the decrypted image is appearing to be corrupted then password may be wrong or it may be file format error"
        )
    except:
        temp_path = input(
            "			Saving file failed!. Enter alternate name without format to save the decrypted file. If it is still failing then check system memory"
        )
        try:
            epath = temp_path + encrypted_image_path
            with open(epath, "wb") as image_file:
                image_file.write(decrypted_image)
            print("			Image saved successully with name " + epath)
            print(
                "			Note: If the decrypted image is appearing to be corrupted then password may be wrong or it may be file format error"
            )
        except:
            print("			Failed! Exiting...")
            exit()


print(
    "--------------------------------------------------------------------------------------------------------------------------------------"
)
print(
    "-------------------------------------------------IMAGE ENCRYPTOR DECRYPTOR TOOL triple-DES-------------------------------------------"
)
print("")
print("")
print("		        You need to provide atleast 8 character long password for secure ")
print("		        encryption.")
print("		        Choose a strong and non-repeating password for best security.")
print(
    "		        This app is capable of encrypting ANY KIND OF FILE <300 MB on 4GB RAM."
)
print("		        With bigger RAM, it can encrypt files larger than that.")
print("")
print("")
print("")
print("")
print(
    "		        CBC Method is applied in this program. The files on which operations are being "
)
print(
    "		        performed should be in same folder. The encrypted and decrypted files by default are saved as"
)
print(
    "		        encrypted_originalname.originalformat and decrypted_originalname.originalformat respectively. "
)
print(
    "		        In some cases, file format error during decryption may occur if image was not encrypted using this program."
)
print("		        The encrypted file is saved in same format as original.")
print("")
print("")


# --------------------------------------MAIN PROGRAM-----------------------------------------------
# Mode selection
try:
    choice = int(input("        Press 1 for Encryption || 2 for Decryption: "))
    while choice != 1 and choice != 2:
        choice = int(input("		      Invalid Choice! Try Again:"))

except:
    print("Error, please provide valid Input")
    exit()


if choice == 1:
    # Encryption Mode, function call
    path = input("		Enter image's name to be encypted:")
    encryptor(path)


else:
    # Decryption mode, function call
    encrypted_image_path = input("		Enter file name to decrypted:")
    decryptor(encrypted_image_path)

print("")
print("")
print(
    "-------------------------------------------------------------------------------------------------------------------------------------"
)
print(
    "--------------------------------------------------------------------------------------------------------------------------------------"
)
