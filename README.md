# Encrypted-Client-Server-Comm

## Overview

This project models a secure communication protocol between a client and a server. The communication protocol uses a hybrid encryption scheme: messages are encrypted using the AES (Advanced Encryption Standard) algorithm, and the AES key is encrypted using the RSA (Rivest-Shamir-Adleman) algorithm. Both AES and RSA implementations are custom and handcrafted.


<div style="text-align: center;">
 ![image](https://github.com/user-attachments/assets/87085d05-1e9c-4421-a87f-4fca6f05e73c)
</div>



**Disclaimer:** This project is not meant for commercial or practical use. It is intended for educational purposes only. Below are some reasons why this implementation is not suitable for production environments:
1. **Insecure Random Number Generation:** The implementations use `rand()` to generate random values, which is not secure. Cryptographically secure random number generators should be used instead.
2. **Potential Side-Channel Attacks:** The implementations may be vulnerable to side-channel attacks, such as timing attacks, which can leak sensitive information.
3. **Lack of Comprehensive Security Measures:** The implementations do not include many essential security features, such as padding schemes, integrity checks, and authenticated encryption, which are crucial for secure communication.

## Requirements

This project requires GMP (GNU Multiple Precision Arithmetic Library) on Windows. GMP is used for handling large numbers in the RSA implementation.

### Download and Install GMP for Windows
1. [GMP for Windows](https://gmplib.org/download/gmp/gmp-6.2.1.tar.lz)
2. Follow the instructions on the GMP website for installation.

## Directory Structure

```
Encrypted-Client-Server-Comm/
├── client.py
├── README.md
├── server.py
├── Makefile
├── Encryption_Algs/
│   ├── AES/
│   │   ├── key_expansion/
│   │   │   └── key_expansion.cpp
│   │   │   └── key_expansion.h
│   │   └── src/
│   │       └── aes.cpp
│   │       └── transformations.cpp
│   │       └── transformations.h
│   ├── RSA/
│       └── helperFunctions.cpp
│       └── helperFunctions.h
│       └── rsa.cpp
└── tests/
    └── test_aes_dll.py
    └── test_rsa_dll.py
```

## Compilation Instructions

To compile the DLL files for AES and RSA, navigate to the top-level directory and run the following command:

```sh
make
```

This will generate `rsa.dll` in the `RSA` directory and `aes.dll` in the `AES` directory.

## Usage


1. Run the server script:

    ```sh
    python server.py
    ```

<img src="https://github.com/user-attachments/assets/6b995e53-d614-4483-9026-0c4a09f7ff3c" width="400" />

2. Run client.py

    ```sh
    python client.py
    ```

<img src="https://github.com/user-attachments/assets/810c9bf2-59c4-42db-9219-87e28a0b40b4" width="700" />

3. Check server.py output


<img src="https://github.com/user-attachments/assets/010c22ec-87c9-4af9-bf56-6088bd41f4bb" width="700" />

## Implementation Details

### AES Encryption

AES (Advanced Encryption Standard) is a symmetric key encryption algorithm. In this project, it is used to encrypt messages before sending them over the network. The AES implementation includes key expansion and the necessary transformation functions.

### RSA Encryption

RSA (Rivest-Shamir-Adleman) is an asymmetric key encryption algorithm. In this project, it is used to encrypt the AES key. The RSA implementation includes key generation, encryption, and decryption functions.

## Important Notes

- The project uses custom implementations of AES and RSA. These implementations are for educational purposes and should not be used in production systems.
- The project uses GMP for handling large numbers in RSA. Ensure that GMP is installed and properly configured on your system.


---
