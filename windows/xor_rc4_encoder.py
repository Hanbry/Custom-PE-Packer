import os
import sys
from Crypto.Cipher import ARC4
import hashlib
import random
import binascii

KEY_LENGTH = 16

def encrypt_file_rc4_xor(input_data):
    # Get Key from random hash bytes
    hash_object = hashlib.sha256(input_data)
    hash_bytes = hash_object.digest()
    start_pos = random.randint(0, len(hash_bytes) - KEY_LENGTH)
    key = hash_bytes[start_pos:start_pos + KEY_LENGTH]

    cipher = ARC4.new(key)
    rc4_crypted_data = cipher.encrypt(input_data)

    xor_crypted_data = bytearray()
    for i in range(len(rc4_crypted_data)):
        key_byte = key[i % KEY_LENGTH]
        encrypted_byte = rc4_crypted_data[i] ^ key_byte
        xor_crypted_data.append(encrypted_byte)

    key_hex_str = binascii.hexlify(key).decode()
    print("Used Key:", key_hex_str)

    return xor_crypted_data
    
def main():
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} input_file_path output_file_path")
        sys.exit(1)
    input_file_path = sys.argv[1]
    output_file_path = sys.argv[2]

    with open(input_file_path, 'rb') as input_file:
        input_data = input_file.read()

    encrypted_data = encrypt_file_rc4_xor(input_data)

    with open(output_file_path, 'wb') as output_file:
        output_file.write(encrypted_data)

if __name__ == '__main__':
    main()
