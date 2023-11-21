def validate_bin_string(binary_string):
    """
    Validate that the input string is made of zeros and ones only.
    """
    for char in binary_string:
        if char not in ("0", "1"):
            raise ValueError("Invalid input string for BinString")


def bitwise_xor(bin_str1, bin_str2):
    """
    Bitwise XOR (^) operation for binary strings.
    """
    validate_bin_string(bin_str1)
    validate_bin_string(bin_str2)

    result = bin(int(bin_str1, 2) ^ int(bin_str2, 2))[2:]
    result = result.zfill(max(len(bin_str1), len(bin_str2)))
    return result


def bitwise_left_shift(binary_string, n):
    """
    Bitwise left shift (<<) operation for binary strings.
    """
    validate_bin_string(binary_string)

    result = binary_string[:]
    for _ in range(n):
        result = result[1:] + result[0]

    return result

