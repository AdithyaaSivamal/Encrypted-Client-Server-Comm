import socket
import ctypes
import os
import signal
import sys
import json
from ctypes import create_string_buffer, c_char_p
from datetime import datetime

# Load AES and RSA DLLs
aes_lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), 'aes.dll'), winmode=0)
rsa_lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), 'rsa.dll'), winmode=0)

# Define AES decryption function with appropriate argument types
aes_lib.decrypt.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
aes_lib.decrypt.restype = None

def aes_decrypt(key, ciphertext_hex):
    """
    Decrypts a ciphertext using the provided AES key.

    Args:
        key (str): The AES key in hexadecimal format.
        ciphertext_hex (str): The ciphertext to decrypt in hexadecimal format.

    Returns:
        bytes: The decrypted plaintext as bytes.
    """
    key_bytes = bytes.fromhex(key)
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    plaintext = (ctypes.c_ubyte * 16)()  # Assuming 128-bit AES

    if len(key_bytes) != 16:
        raise ValueError("Key must be 16 bytes (32 hex characters)")
    if len(ciphertext_bytes) != 16:
        raise ValueError("Ciphertext must be 16 bytes (32 hex characters)")

    key_array = (ctypes.c_ubyte * 16).from_buffer_copy(key_bytes)
    ciphertext_array = (ctypes.c_ubyte * 16).from_buffer_copy(ciphertext_bytes)

    aes_lib.decrypt(key_array, ciphertext_array, plaintext)

    decrypted_bytes = bytes(plaintext)
    return decrypted_bytes

# Define RSA decryption function with appropriate argument types
rsa_lib.decrypt.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
rsa_lib.decrypt.restype = None

# Define RSA key generation function with appropriate argument types
rsa_lib.generateRSAKeys.argtypes = [c_char_p, c_char_p, c_char_p]

def rsa_decrypt(ciphertext_hex, d, n):
    """
    Decrypts a ciphertext using the provided RSA private key components.

    Args:
        ciphertext_hex (str): The ciphertext to decrypt in hexadecimal format.
        d (str): The RSA private exponent in hexadecimal format.
        n (str): The RSA modulus in hexadecimal format.

    Returns:
        str: The decrypted plaintext in hexadecimal format.
    """
    ciphertext = create_string_buffer(ciphertext_hex.encode('utf-8'))
    d_str = create_string_buffer(d.encode('utf-8'))
    n_str = create_string_buffer(n.encode('utf-8'))
    decrypted = create_string_buffer(1024)

    rsa_lib.decrypt(ciphertext, d_str, n_str, decrypted)
    return decrypted.value.decode('utf-8')

def log_message(message):
    """
    Logs a message with the current timestamp to a log file.

    Args:
        message (str): The message to log.
    """
    with open('logs.txt', 'a') as log_file:
        log_file.write(f"{datetime.now()} - {message}\n")

def signal_handler(sig, frame):
    """
    Signal handler for graceful shutdown on Ctrl+C.

    Args:
        sig: Signal number.
        frame: Current stack frame.
    """
    print("\nServer shutting down.")
    log_message("Server shut down.")
    server_socket.close()
    sys.exit(0)

# Set up signal handler for graceful shutdown
signal.signal(signal.SIGINT, signal_handler)

# Set up the server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 65432))
server_socket.listen(5)
print("Server listening on port 65432")
log_message("Server started and listening on port 65432.")

# Allocate buffers for RSA keys
n = create_string_buffer(1024)
e = create_string_buffer(1024)
d = create_string_buffer(1024)

# Generate RSA keys
print("Generating RSA keys...")
rsa_lib.generateRSAKeys(n, e, d)
print("RSA keys generated.")
log_message(f"RSA keys generated. Public key: (n={n.value.decode('utf-8')}, e={e.value.decode('utf-8')})")

# Store the public key components
public_key = {'n': n.value.decode('utf-8'), 'e': e.value.decode('utf-8')}

while True:
    client_socket, addr = server_socket.accept()
    print(f"\nConnection established with {addr}")
    log_message(f"Connection established with {addr}")

    try:
        # Send the public key to the client
        client_socket.sendall(json.dumps(public_key).encode('utf-8'))
        print("Public key sent to the client.")
        log_message("Public key sent to the client.")

        # Receive the JSON data from the client
        data_received = client_socket.recv(2048).decode('utf-8')
        data = json.loads(data_received)
        encrypted_aes_key = data['encrypted_aes_key']
        encrypted_message = data['encrypted_message']

        print(f"Received encrypted AES key: {encrypted_aes_key}")
        print(f"Received encrypted message: {encrypted_message}")
        log_message(f"Received encrypted AES key: {encrypted_aes_key}")
        log_message(f"Received encrypted message: {encrypted_message}")

        # Decrypt AES key using RSA private key
        aes_key_hex = rsa_decrypt(encrypted_aes_key, d.value.decode('utf-8'), n.value.decode('utf-8'))
        aes_key_hex = aes_key_hex.zfill(32)  # Ensure the key is 32 hex characters
        print(f"Decrypted AES key: {aes_key_hex}")
        log_message(f"Decrypted AES key: {aes_key_hex}")

        # Decrypt the message using the decrypted AES key
        decrypted_bytes = aes_decrypt(aes_key_hex, encrypted_message)
        plaintext = decrypted_bytes.rstrip(b'\x00').decode('utf-8')
        print(f"Decrypted message: {plaintext}")
        log_message(f"Decrypted message: {plaintext}")

    except UnicodeDecodeError:
        print("Error: Decrypted message contains non-printable characters.")
        log_message("Error: Decrypted message contains non-printable characters.")
    except Exception as e:
        print(f"Error: {e}")
        log_message(f"Error: {e}")
    finally:
        client_socket.close()
        print("Connection closed.")
        log_message("Connection closed.")
