# convert a.png to binary
with open("D:\\Crypto Project\\bob-shared-key.txt", "rb") as imagefile:
    image = imagefile.read()


print(image[:8])
print(image[8:16])
print(image[16:24])
print(len(image))

# with open("decrypted_abc.png", "rb") as imagefile:
#     image1 = imagefile.read()

# # padding
# while len(image1) % 8 != 0:
#     image1 += b" "
# image_int1 = int.from_bytes(image1, byteorder="big")

# # Convert integer to binary string
# image_bin1 = bin(image_int1)[2:]
# print(image_bin1)

# print(image_bin == image_bin1)


# # Two byte strings
# bytes1 = b"\xceAD\xcd\xb3\xf4\xebLukn\xb2\x05\x82\x84\x9c\xd3\xe5`\xf3\xaf\xa6\xe8\xa5\x94\xa8gv\xb7t\xe2\x04"
# bytes2 = b"\xf8k\x04U\x1e\xbf\n\x10i\xc9\x14\x17\xb1\x8cI\x8e\xe4\r\x08\xf5\xc3\x95\xb7\xb1st\xef\x8d}@\xcb="

# # Convert byte strings to bits
# bits1 = "".join(format(byte, "08b") for byte in bytes1)
# bits2 = "".join(format(byte, "08b") for byte in bytes2)

# # Check if the lengths of bits are the same
# if len(bits1) == len(bits2):
#     print("The lengths in bits are the same.")
# else:
#     print("The lengths in bits are different.")
