import lief
import argparse
import os
import sys
from Crypto.Cipher import ARC4
import hashlib
import random
import binascii
import shutil

KEY_LENGTH = 16
PRIME_LENGTH = 8
PRIME_TOP = 60124

def prime_number(n):
    is_prime = [True] * (n+1)
    is_prime[0] = is_prime[1] = False
    for number in range(2, int(n**0.5)+1):
        if is_prime[number]:
            for multiple in range(number*number, n+1, number):
                is_prime[multiple] = False
    return max([number for number, prime in enumerate(is_prime) if prime])


def encrypt_file_rc4_xor(input_data):
    # Get Key from random hash bytes
    hash_object = hashlib.sha256(input_data)
    hash_bytes = hash_object.digest()
    start_pos = random.randint(0, len(hash_bytes) - KEY_LENGTH)
    key = hash_bytes[start_pos:start_pos + KEY_LENGTH]

    prime_num = prime_number(PRIME_TOP)
    print("Last prime: ", prime_num)

    cipher = ARC4.new(key)
    rc4_crypted_data = cipher.encrypt(input_data)

    xor_crypted_data = bytearray()
    for i in range(len(rc4_crypted_data)):
        key_byte = key[i % KEY_LENGTH]
        encrypted_byte = rc4_crypted_data[i] ^ key_byte
        xor_crypted_data.append(encrypted_byte)

    # Obfuscate key
    obfu_key = bytearray()
    prime_num_bytes = prime_num.to_bytes(PRIME_LENGTH, byteorder='little')
    for i in range(KEY_LENGTH):
        prime_byte = prime_num_bytes[i % PRIME_LENGTH]
        encrypted_key_byte = key[i] ^ prime_byte
        obfu_key.append(encrypted_key_byte)

    key_hex_str = binascii.hexlify(key).decode()
    obfu_key_hex_str = binascii.hexlify(obfu_key).decode()
    print("Used Key: ", key_hex_str)
    print("Obfuscated Key: ", obfu_key_hex_str)

    return (xor_crypted_data, obfu_key_hex_str)



def align(x, al):
    """ return <x> aligned to <al> """
    if x % al == 0:
        return x
    else:
        return x - (x % al) + al

def pad_data(data, al):
    """ return <data> padded with 0 to a size aligned with <al> """
    return data + ([0] * (align(len(data), al) - len(data)))


    
def main():
    parser = argparse.ArgumentParser(description='Pack PE binary')
    parser.add_argument('input', metavar="FILE", help='input file')
    parser.add_argument('-p', metavar="UNPACKER", help='unpacker .exe', required=True)
    parser.add_argument('-o', metavar="FILE", help='output', default="packed.exe")

    args = parser.parse_args()

    # open the unpack.exe binary
    unpack_PE = lief.PE.parse(args.p)

    # we're going to keep the same alignment as the ones in unpack_PE,
    # because this is the PE we are modifying
    file_alignment = unpack_PE.optional_header.file_alignment
    section_alignment = unpack_PE.optional_header.section_alignment

    # read the whole file to be packed
    with open(args.input, "rb") as f:
        input_PE_data = f.read()

    packed_data = list(input_PE_data) # lief expects a list, not a "bytes" object.
    packed_data = pad_data(packed_data, file_alignment) # pad with 0 to align with file alignment (removes a lief warning)

    packed_section = lief.PE.Section(".packed")
    packed_section.content = packed_data
    packed_section.size = len(packed_data)
    packed_section.characteristics = (lief.PE.SECTION_CHARACTERISTICS.MEM_READ
                                    | lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE
                                    | lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA)
    # We don't need to specify a Relative Virtual Address here, lief will just put it at the end, that doesn't matter.
    unpack_PE.add_section(packed_section)

    # remove the SizeOfImage, which should change, as we added a section. Lief will compute this for us.
    unpack_PE.optional_header.sizeof_image = 0


    # save the resulting PE
    if(os.path.exists(args.o)):
        # little trick here : lief emits no warning when it cannot write because the output
        # file is already opened. Using this function ensure we fail in this case (avoid errors).
        os.remove(args.o)

    builder = lief.PE.Builder(unpack_PE)
    builder.build()
    builder.write(args.o)

if __name__ == '__main__':
    main()
