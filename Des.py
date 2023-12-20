from Constants import PC_1, PC_2, E, Sbox, P, PI_1, IP
from BinaryOps import bitwise_xor


img = "1000100101010000010011100100011100001101000010100001101000001010000000000000000000000000000011010100100101001000010001000101001000000000000000000000000001101011000000000000000000000000101000110000100000000110000000000000000000000000100011010000010011100000110101010000000000000000000000000000000101110011010100100100011101000010000000001010111011001110000111001110100100000000000000000000000000000100011001110100000101001101010000010000000000000000101100011000111100001011111111000110000100000101000000000000000000000000000010010111000001001000010110010111001100000000000000000001011000100101000000000000000000010110001001010000000101001001010100100010010011110000000000000000000000100001011110010100100101000100010000010101010001111000010111101110110111011101000010111011010001101110110101010001010000000111111100000111110111001110111101011000101001010010110010010010101101000100010010010100100100101111100100010001111000101010100100010011110000101011100010101111010000011000100010101101110000001010100101110010000110001101100100100100011101010010011011101010010010000100101000011001000000110010101001000011110001000010101110010010001001001001100010010010001001001001010010011110111100010010000100011000101010011110000101001010100100010100011110010110111011111011001101111011101111110011101100111100111001110111101111110111001111101111001110010111010111001111001111010111011101111111111101100111111110001100001101011111011001101011001111011110011101111111110011101011100111100110010110100111101101111111111001110101010001110101110010111111000010011111111111111111110001100111010011001011101011101001101001101001101111101010100011010011011011011010101010000111111011010000100000110001111001010100110011111001100000110001101000110001111000011101000111011110110110100101111001011001011001011011101011101011111011111000111000101000101111101011011111111111111111111011110111111011110110110010111101110001011101010111010111100111100101100101110101001010101101111110111011010110010100111010111101001101000001000011111001111110011000011000000010110110110111111110111000110001111111111111101010001111011111011011011011111011111111111010000000010000111101111000010000001010111110011100111000111110101010101011101011110101111001011111011111011111010111010101011100110111001100101110000110001010110100100011100010111110000011111111111110011100111101111111100001100000000011111110111101001010011100111111110101010111101111101100101100010100011100010000111101011100000000000111001111100111000010001100111100001001011001011001011001101001100111111010100110000110001110001110100010011011110000001011000000111000010001111110110101110101110101110111110101011101101101101111101111111111110110011000011101100000100011111101100100011000111101111100011001000111110111011110011110011110011111010101111111111111101011010111101111111110011011100110100111100001011110010111010111100111101001101001101111011101001001001010001010110100010110011001100100011001000110010001001010001111011111110000100001110011111110111100001111101110001010001000001000110110001000101100000100110101000110100100010101101001001001000101001010000111111111111111111110111101111111101011010011110111110011100010000100111111010110100011000111111111110111101000110100001101100000010100000111101110001000001000100011111010011011011111011100111100111100111101100100011111111111111110010110001001010010110010111010101101000011011110000010010010011110011100010100000011111111100010000100011000111110001000111101100011001000010001111110001000000100000111000111100001100001000100110010101101101111011111010101100101100111111110111100001100001100001111000011111010010101000010100101101011111000101010110011110010101111011100011100001100001100001101000100111110101001100111011010111100100001001010010000010010010001011001010001110001111101111101011101001011110111110100110100100100101111110111101101000011010000000111001011111110110110111111111111111111111011110101011011011011011111011101000101100001101001111011010111111100100100101010110110110110001110011101000101110101110001110000010000011011110111100110100110100110101110000110101100000010010111101101001110001010111010110101110101100101101011110101101101011101011101011110000110111111100100000110101101010101010111010110111100011011011110111111111111011010110111011110011011011011011111011101110001101001000001000101101110011111011011011100011100111100111101111000100111100110110111110110110101111001000101011000111011001100100111001010110000010100101001001000001100101010100011010011010011100011101100101101001101001101101010000000100100110010110011001001111000000111011111011010011010011010011100010000110010101000001000000110001111100001111011100100110101110100111010010110110101011010111001111001011100011001001101001101001101101110100100101001010001011010011010000111001111001110010000100001111101010110000110000111000111010001011011100101000001100001000110010101110010000011101011110101111111011011001011001011001011101010101101010111010111100111100111100101010111100001110111101010011111001101100011000011000111100101011011001111100110010011001101100111100011000111001000001101101010101010101100110101011001000001100110101100010001001100001100110111110110000110000010000011001000001100011001100000100100110010110011010111010110110110110110110101010101010111110111100011100011010011011101000110101111101100100101000010000110011010010001011100011100111100110100110101111101011110111101111111111111111111101100010000000111001101011101110101110010110010110110110111110101001101101101101110101110110110110101001111001000010101001011001000110110101101101101110010110010110010110111101011110110110110111110111111001111011100101010001111010001110001010010100100111100001000110111100011101011110111111111111101011010110101100000111110101000100111001100001100001011000111010010001101001101011101011010101000001011111011101011101000101000101110100011000111011110001100010010110111110000100000110111100110010000001011100110011011011101011101011101011101001101110000011001001001011100001000100010101010101010100010101010001110000001100111101111001001001001011001011110000100111101100001101011110000111111001000010000000111001010010100000010111000111100111100111000111011011000111000111001011011011110111110110110110101010000111110101111010111010111110111111111111101111110101101010001010011010011110000110111010010011001101100110110011010010101010010111110110001110001000001001011110011100100000110010110101110101111001111000011000010000010111000001111010100100010010010000011000111101000000110111111010111010111010111011101011101010001001000001010100101001110110100010111011110101011101011101111101110000110101110010010110111100110100010110010011101101001111110000100011011011011111011110001110001100011111010000000100100010010010111101011101100011000110001111101011011100111110111000111000110000110010011000101000000110000101001000000010110000001000111010100100010100101101010011010001011001010001011100110100010101011000000111100101001000010000101101001111110111110011110010111000111101101001001001101100100001011011011100111100100100100101111010110111110111110111110111000011011010000011000010101111010101001001000100100100000000010011001001100111110111101001010000100001111000001010100100110011001100100001011011011101100101100101100101111010110101001111001110001110010010010100101100010110100001111001111001010010111101001000010110111110110011001000001000111111100110011010011011111011111010111001110111110111110111110111110111000110001101000000111111011100001101011011011000011000010000010101111010101001001001001111001110100010100111110010101001000010000100000111011010010110010000111111111001000101001011100111110001010001001001001111101011000001111011111011110100001000011101000111010111010101100000101110010000100100110111111101111001001011110101101101110011100011001000010111110000001101110110100111000101000100111110110100110011000001010010111110111111000010110101101001111100111100110100110111000111100100001010010110001101101001111011110111101101011010011011000100101111001010011011101111111111101111000000101100111101110110010011010001111111001011110011110111110110100010101110110100110110001010000100001000100010101101000100100100011000011111010101010001010001110001110000010101000000101001101010101100111000011110010110010011011111111001101001101101101101101000100101111011111110101001010100100000010100111101111111001011111110111101101101101101101101100101110001000100100110101100101110010111111011000110010010011010000010001001001110000101001100101100111100111100001100111001010100101101000010010101001000111110110100101011011011011001011000101000101101110001110000011001100100101110110110100101100110101100110010011011101011100011100011100011101111000010010111011111000"



def _group_by(string, by):
    # Returns groups the block of message into 64 bits for input

    # Pad the string with zeros if needed to make the last block valid input
    padding_needed = (by - (len(string) % by)) % by
    padded_string = string + "0" * padding_needed

    return [padded_string[i : i + by] for i in range(0, len(padded_string), by)]


def _permute_with(string, permutation):
    # Returns the string in order of the permutation mentioned in the permutation argument

    return "".join([string[i - 1] for i in permutation])


def f(r, k):
    # F function

    # Expansion of half from 32 to 48 bits
    e = _permute_with(r, E)
    # XOR with the subkey
    k_xor_e = bitwise_xor(k, e)


    # S box substitution to change from 6 bits to 4 bits
    S = ""
    blocks = _group_by(k_xor_e, 6)

    for n in range(8):
        # i = 2 bit value of first and last bit
        i = int(blocks[n][0] + blocks[n][-1], 2)

        # j = 4 bit value of middle 4 bits
        j = int(blocks[n][1:-1], 2)

        # Look up the value in the S box
        S += bin(Sbox[n][i][j])[2:].zfill(4)

    # Transposition of 32 bits
    return _permute_with(S, P)


def encrypt(message, key_main, length_image, **kwargs):
    # DES Encryption algorithm

    # Key conversion to binary
    key_int = int.from_bytes(key_main, byteorder="big")
    key = bin(key_int)[2:]
    # print(key)
    print(len(key))

    assert len(key) > 0, "No input key to perform encryption"

    # Generating subkeys

    pc1_key = _permute_with(key, PC_1)
    # Split and store left and right halves of the key (28 bit) in separate lists
    C = [pc1_key[:28]]
    D = [pc1_key[28:]]

    # Shift left by 1 or 2 bits depending on the round and append to the list of subkeys
    for i in range(16):
        shift = 1 if i in (0, 1, 8, 15) else 2
        C.append(bin(int(C[-1], 2) << shift)[2:].zfill(28))
        D.append(bin(int(D[-1], 2) << shift)[2:].zfill(28))

    # List of subkeys
    K = []
    for i in range(16):
        CD = C[i + 1] + D[i + 1]
        K.append(_permute_with(CD, PC_2))

    # Reverse the list of subkeys if decrypting
    if kwargs.get("decrypt"):
        K = list(reversed(K))

    # Message encryption
    result = ""

    # Split message into blocks and run 16 rounds of encryption for each block
    for block in _group_by(message, 64):
        # Initial permutation for input
        PI = _permute_with(block, IP)

        # Split into 2 halves
        L = [PI[:32]]
        R = [PI[32:]]

        # Rounds
        for i in range(16):
            Ln = R[-1]
            Rn = bitwise_xor(L[-1], f(R[-1], K[i]))

            # Result of the round
            L.append(Ln)
            R.append(Rn)

        # Final permutation
        RL = R[-1] + L[-1]

        # Inverse permutation
        result += _permute_with(RL, PI_1)

    return result


def decrypt(string, key_main, length, **kwargs):
    # DES Decryption algorithm

    result = encrypt(string, key_main, length, decrypt=True, **kwargs)
    result = result[:length]
    return result


if __name__ == "__main__":
    print("DES Encryption and Decryption")
    print("\n")
    print("Encrypting and decrypting a string hardcoded in the program")

    # Create ciphertext
    cipher = encrypt(
        img,
        b"\xf8\xfd\x8f\x13\xe8\xad\xf7\xa5",
        len(img),
    )
    print("Encrypted text: %s" % cipher)
    # print(type(cipher))

    # Decipher it to plaintext
    decipher = decrypt(
        cipher,
        b"\xf8\xfd\x8f\x13\xe8\xad\xf7\xa5",
        len(img),
    )
    # print(len(decipher))
    print("Decrypted text: %s" % decipher)

    # Check if the original and deciphered text are the same
    if img == decipher:
        print("Success")
    else:
        print("Failed")