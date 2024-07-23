import ctypes
import os
import threading
from ctypes import create_string_buffer, c_char_p

# Function to call generateRSAKeys and handle the timeout
def call_generateRSAKeys(n, e, d, timeout):
    def target(result, n, e, d):
        try:
            print("Generating RSA keys...")
            rsa.generateRSAKeys(n, e, d)
            print("RSA keys generated.")
            result.append(True)
        except Exception as e:
            print(f"An error occurred in thread: {e}")
            result.append(False)

    result = []
    thread = threading.Thread(target=target, args=(result, n, e, d))
    thread.start()
    thread.join(timeout)

    if thread.is_alive():
        print("Error: Function execution timed out")
        return False
    return result[0] if result else False

# Load the RSA DLL
aes_lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__),'../Encryption_Algs/RSA' ,'rsa.dll'), winmode=0)

# Define RSA function prototypes
rsa.generateRSAKeys.argtypes = [c_char_p, c_char_p, c_char_p]
rsa.encrypt.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
rsa.decrypt.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]

# Allocate buffers for keys
n = create_string_buffer(1024)
e = create_string_buffer(1024)
d = create_string_buffer(1024)

# Set the timeout duration (in seconds)
TIMEOUT_DURATION = 30  # Increase the timeout duration

# Call generateRSAKeys with timeout
if call_generateRSAKeys(n, e, d, TIMEOUT_DURATION):
    # Example AES key (16 bytes for AES-128)
    aes_key_hex = "00112233445566778899aabbccddeeff"

    # Convert AES key to an integer string for RSA
    aes_key_int = int(aes_key_hex, 16)
    aes_key_int_str = f"{aes_key_int:x}"
    

    # Allocate buffer for encrypted AES key
    encrypted_aes_key = create_string_buffer(1024)
    decrypted_aes_key = create_string_buffer(1024)

    print("Encrypting the AES key...")
    # Encrypt the AES key with RSA
    rsa.encrypt(c_char_p(aes_key_int_str.encode('utf-8')), e, n, encrypted_aes_key)
    print("AES key encrypted.")

    print("Decrypting the AES key...")
    # Decrypt the AES key with RSA
    rsa.decrypt(encrypted_aes_key, d, n, decrypted_aes_key)
    print("AES key decrypted.")

    # Convert decrypted AES key back to integer and then to hex string
    decrypted_aes_key_int = int(decrypted_aes_key.value.decode('utf-8'), 16)
    decrypted_aes_key_hex = f"{decrypted_aes_key_int:032x}"

    # Ensure decrypted AES key matches the original AES key
    if decrypted_aes_key_hex != aes_key_hex:
        print(f"Error: Decrypted AES key does not match the original. Decrypted: {decrypted_aes_key_hex}")
    else:
        print(f"Success: AES key encryption and decryption with RSA worked correctly.")

        print(f'Public key: (n={n.value.decode("utf-8")}, e={e.value.decode("utf-8")})')
        print(f'Private key: (d={d.value.decode("utf-8")}, n={n.value.decode("utf-8")})')
        print(f'Original AES key: {aes_key_hex}')
        print(f'Encrypted AES key: {encrypted_aes_key.value.decode("utf-8")}')
        print(f'Decrypted AES key: {decrypted_aes_key_hex}')
else:
    print("RSA key generation failed due to timeout")

