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

### Decryption Function

You'll have to use the following decryption function to succesfully decrypt the contents of the payload.h

```bash
int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
        return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
        return -1;
    }
    if (!CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
        return -1;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
        return -1;
    }
    if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
        return -1;
    }
    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}

```


## Output

The script generates the following output files:

"shellcode.h": Contains the encrypted data as an unsigned char array named "shellcode" along with its size.
"AESkey.txt": Contains the AES key required for decryption.

### Note

A new AES key is generated each time the script is run. Make sure to keep the "AESkey.txt" file safe in order to decrypt your data.

Feel free to customize the script according to your specific requirements
