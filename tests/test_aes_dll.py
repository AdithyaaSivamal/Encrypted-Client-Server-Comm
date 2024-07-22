import ctypes
import os

# Load the DLL file
aes_lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), 'aes.dll'), winmode=0)

# Define the AES encryption and decryption functions
aes_lib.encrypt.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
aes_lib.encrypt.restype = None
aes_lib.decrypt.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
aes_lib.decrypt.restype = None

def aes_encrypt(key, plaintext):
    key_bytes = bytes.fromhex(key)
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext = (ctypes.c_ubyte * 16)()  # Assuming 128-bit AES

    # Ensure key and plaintext are correctly padded/truncated to 16 bytes
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

#-------fAIL--------#
def aes_decrypt(key, ciphertext_hex): 
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
    return bytes(plaintext).rstrip(b'\x00').decode('utf-8')

key = "00112233445566778899aabbccddeeff"
plaintext = "This is a test"
expected_ciphertext = bytes.fromhex('3c86e7ec17bb967b9da2f2242d94a634')

# Encrypt plaintext using the provided key
ciphertext = aes_encrypt(key, plaintext)

print(f"Ciphertext: {ciphertext.hex()}")
print(f"Expected ciphertext: {expected_ciphertext.hex()}")

# Check if the ciphertext matches the expected value
if ciphertext != expected_ciphertext:
    print(f"Error: The AES encryption function did not produce the expected ciphertext.")
else:
    print("Success: The AES encryption function produced the expected ciphertext.")

# Decrypt the ciphertext using the provided key
decrypted_text = aes_decrypt(key, ciphertext.hex())
print(f"Decrypted text: {decrypted_text}")

# Check if the decrypted text matches the original plaintext
if decrypted_text == plaintext:
    print("Success: The AES decryption function worked correctly.")
else:
    print("Error: The AES decryption function did not produce the expected output.")

