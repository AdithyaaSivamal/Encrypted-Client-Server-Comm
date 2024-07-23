import socket
import ctypes
import os
import json
import secrets
from ctypes import create_string_buffer, c_char_p

# Load AES and RSA DLLs
aes_lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__),'./Encryption_Algs/AES','aes.dll'), winmode=0)
rsa_lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), './Encryption_Algs/RSA','rsa.dll'), winmode=0)

# Define AES encryption function
aes_lib.encrypt.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
aes_lib.encrypt.restype = None

def aes_encrypt(key, plaintext):
    """
    Encrypts a plaintext message using the provided AES key.

    Args:
        key (str): The AES key in hexadecimal format.
        plaintext (str): The plaintext message to encrypt.

    Returns:
        bytes: The encrypted ciphertext as bytes.
    """
    key_bytes = bytes.fromhex(key)
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext = (ctypes.c_ubyte * 16)()  # Assuming 128-bit AES

    if len(key_bytes) != 16:
        raise ValueError("Key must be 16 bytes (32 hex characters)")
    if len(plaintext_bytes) > 16:
        raise ValueError("Plaintext must be at most 16 bytes")
    if len(plaintext_bytes) < 16:
        plaintext_bytes += b'\x00' * (16 - len(plaintext_bytes))  # Pad with null bytes if necessary

    key_array = (ctypes.c_ubyte * 16).from_buffer_copy(key_bytes)
    plaintext_array = (ctypes.c_ubyte * 16).from_buffer_copy(plaintext_bytes)

    aes_lib.encrypt(key_array, plaintext_array, ciphertext)
    return bytes(ciphertext)

# Define RSA encryption function
rsa_lib.encrypt.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
rsa_lib.encrypt.restype = None

def rsa_encrypt(message_hex, e, n):
    """
    Encrypts a message using the provided RSA public key components.

    Args:
        message_hex (str): The message to encrypt in hexadecimal format.
        e (str): The RSA public exponent in hexadecimal format.
        n (str): The RSA modulus in hexadecimal format.

    Returns:
        str: The encrypted message in hexadecimal format.
    """
    message = create_string_buffer(message_hex.encode('utf-8'))
    e_str = create_string_buffer(e.encode('utf-8'))
    n_str = create_string_buffer(n.encode('utf-8'))
    encrypted = create_string_buffer(1024)

    rsa_lib.encrypt(message, e_str, n_str, encrypted)
    return encrypted.value.decode('utf-8')

# Generate a random AES key
def generate_aes_key():
    """
    Generates a random 128-bit AES key.

    Returns:
        str: The AES key in hexadecimal format.
    """
    return secrets.token_hex(16)

# Connect to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 65432))

# Receive the public key from the server
public_key_data = client_socket.recv(2048).decode('utf-8')
public_key = json.loads(public_key_data)
n = public_key['n']
e = public_key['e']

# Generate a random AES key
aes_key_hex = generate_aes_key()
print(f"Generated AES key: {aes_key_hex}")

# Take user input for the message
plaintext = input("Enter the message to encrypt and send to the server: ")

# Encrypt the AES key with RSA
encrypted_aes_key = rsa_encrypt(aes_key_hex, e, n)
print(f"Encrypted AES key: {encrypted_aes_key}")

# Encrypt the message with AES
ciphertext = aes_encrypt(aes_key_hex, plaintext)
ciphertext_hex = ciphertext.hex()
print(f"Encrypted message: {ciphertext_hex}")

# Send the encrypted AES key and the encrypted message to the server
data = {
    'encrypted_aes_key': encrypted_aes_key,
    'encrypted_message': ciphertext_hex
}
client_socket.sendall(json.dumps(data).encode('utf-8'))

print("Message sent to server")

client_socket.close()
