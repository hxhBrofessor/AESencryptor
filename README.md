# AESencryptor

This Python script is designed to perform AES encryption on a binary file. It uses the pycryptodome library to manage encryption, padding, and key generation processes. The encrypted payload is written to a file named "shellcode.h", and the AES key is stored in "AESkey.txt". The "shellcode.h" file can be included in your C++ source file (e.g., main.cpp) for compiling and further execution.

## Usage

1. Place your binary file in the specified directory.
2. Run the script by executing the following command in the terminal:

To run this script, type:

```bash
python3 AESencryptor.py
```

The script will encrypt the content of the binary file and write the encrypted data into "shellcode.h" and "AESkey.txt". Please note that the script is currently configured to search for a file named "beacon_x64.bin" in the directory. If the file is not found, the program will exit.

## Integration

1. Include the "shellcode.h" file in your C++ source file.
2. Use the AES key stored in "AESkey.txt" to decrypt the data in your C++ code.


### Output

The script generates the following output files:

"shellcode.h": Contains the encrypted data as an unsigned char array named "shellcode" along with its size.
"AESkey.txt": Contains the AES key required for decryption.

### Note

A new AES key is generated each time the script is run. Make sure to keep the "AESkey.txt" file safe in order to decrypt your data.

Feel free to customize the script according to your specific requirements
