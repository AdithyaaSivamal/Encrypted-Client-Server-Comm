#include <iostream>
#include <vector>
#include <ctime>
#include <cstdlib>
#include <gmp.h>
#include <string>
#include "helperFunctions.h"

/**
 * RSA Encryption/Decryption Implementation
 *
 * This implementation uses the GNU MP Bignum Library (GMP) for handling large numbers.
 * GMP is required to compile and run this code. You can download GMP for Windows from:
 * - https://gmplib.org/
 * - https://windows.mpir.org/
 *
 * Ensure that GMP is correctly installed and accessible in your development environment.
 *
 * Compilation Instructions:
 * To compile this code into a DLL that can be accessed by the client-server code,
 * use the following command:
 * g++ -shared -o rsa.dll rsa.cpp helperFunctions.cpp -lgmp -lgmpxx
 *
 * This will generate `rsa.dll` which can be used in conjunction with the client-server
 * architecture to perform RSA encryption and decryption operations.
 */

extern "C" {

    /**
     * Generates RSA key pair (public key: n, e and private key: d).
     * The keys are stored as hexadecimal strings.
     *
     * @param n_str Output buffer for the modulus n (hexadecimal string).
     * @param e_str Output buffer for the public exponent e (hexadecimal string).
     * @param d_str Output buffer for the private exponent d (hexadecimal string).
     */
    __declspec(dllexport) void generateRSAKeys(char* n_str, char* e_str, char* d_str) {
        // Initialize random state
        gmp_randstate_t state;
        initializeRandomState(state);

        // Initialize GMP variables
        mpz_t p, q, n, phi, e, d;
        mpz_inits(p, q, n, phi, e, d, nullptr);

        // Generate two distinct large primes p and q
        do {
            generateLargePrime(p, state, 64);
            generateLargePrime(q, state, 64);
        } while (mpz_cmp(p, q) == 0);  // Ensure p != q

        // Calculate n = p * q
        mpz_mul(n, p, q);

        // Calculate phi = (p-1) * (q-1)
        mpz_t p_minus_1, q_minus_1;
        mpz_inits(p_minus_1, q_minus_1, nullptr);
        mpz_sub_ui(p_minus_1, p, 1);
        mpz_sub_ui(q_minus_1, q, 1);
        mpz_mul(phi, p_minus_1, q_minus_1);

        // Generate public exponent e such that 1 < e < phi and gcd(e, phi) = 1
        do {
            mpz_urandomm(e, state, phi);
            mpz_add_ui(e, e, 2); // Ensure e is at least 2
        } while (mpz_gcd_ui(nullptr, e, mpz_get_ui(phi)) != 1);

        // Calculate private exponent d as the modular inverse of e mod phi
        modInverse(d, e, phi);

        // Convert GMP variables to hexadecimal strings
        mpz_get_str(n_str, 16, n);
        mpz_get_str(e_str, 16, e);
        mpz_get_str(d_str, 16, d);

        // Clear GMP variables
        mpz_clears(p, q, n, phi, e, d, p_minus_1, q_minus_1, nullptr);
        gmp_randclear(state);
    }

    /**
     * Encrypts a message using the RSA public key (e, n).
     *
     * @param message_str The message to encrypt (hexadecimal string).
     * @param e_str The public exponent e (hexadecimal string).
     * @param n_str The modulus n (hexadecimal string).
     * @param result_str Output buffer for the encrypted message (hexadecimal string).
     */
    __declspec(dllexport) void encrypt(const char* message_str, const char* e_str, const char* n_str, char* result_str) {
        // Initialize GMP variables
        mpz_t message, e, n, result;
        mpz_inits(message, e, n, result, nullptr);

        // Convert input strings to GMP variables
        mpz_set_str(message, message_str, 16);
        mpz_set_str(e, e_str, 16);
        mpz_set_str(n, n_str, 16);

        // Perform RSA encryption: result = message^e mod n
        mpz_powm(result, message, e, n);

        // Convert the result to a hexadecimal string
        mpz_get_str(result_str, 16, result);

        // Clear GMP variables
        mpz_clears(message, e, n, result, nullptr);
    }

    /**
     * Decrypts a ciphertext using the RSA private key (d, n).
     *
     * @param ciphertext_str The ciphertext to decrypt (hexadecimal string).
     * @param d_str The private exponent d (hexadecimal string).
     * @param n_str The modulus n (hexadecimal string).
     * @param result_str Output buffer for the decrypted message (hexadecimal string).
     */
    __declspec(dllexport) void decrypt(const char* ciphertext_str, const char* d_str, const char* n_str, char* result_str) {
        // Initialize GMP variables
        mpz_t ciphertext, d, n, result;
        mpz_inits(ciphertext, d, n, result, nullptr);

        // Convert input strings to GMP variables
        mpz_set_str(ciphertext, ciphertext_str, 16);
        mpz_set_str(d, d_str, 16);
        mpz_set_str(n, n_str, 16);

        // Perform RSA decryption: result = ciphertext^d mod n
        mpz_powm(result, ciphertext, d, n);

        // Convert the result to a hexadecimal string
        mpz_get_str(result_str, 16, result);

        // Clear GMP variables
        mpz_clears(ciphertext, d, n, result, nullptr);
    }
}

int main(int argc, char* argv[]) {
    srand(static_cast<unsigned int>(time(0)));

    if (argc < 2 || argc > 3) {
        std::cerr << "Usage: " << argv[0] << " <hex_message> [-i]\n";
        return 1;
    }

    bool detailedOutput = (argc == 3 && std::string(argv[2]) == "-i");

    // Dynamically allocate buffers to avoid stack overflow
    char *n_str = new char[1024];
    char *e_str = new char[1024];
    char *d_str = new char[1024];

    // Generate RSA keys
    generateRSAKeys(n_str, e_str, d_str);

    const char* message_str = argv[1];

    // Dynamically allocate buffers to avoid stack overflow
    char *ciphertext_str = new char[1024];
    char *decrypted_message_str = new char[1024];

    // Encrypt and decrypt the message
    encrypt(message_str, e_str, n_str, ciphertext_str);
    decrypt(ciphertext_str, d_str, n_str, decrypted_message_str);

    // Display the results
    if (detailedOutput) {
        displayEnhancedOutput(std::stoull(message_str, nullptr, 16), std::stoull(message_str, nullptr, 16), 
            std::stoi(n_str, nullptr, 16), std::stoi(n_str, nullptr, 16), 
            std::stoull(n_str, nullptr, 16), std::stoull(n_str, nullptr, 16), 
            std::stoull(e_str, nullptr, 16), std::stoull(d_str, nullptr, 16), 
            std::stoull(ciphertext_str, nullptr, 16), std::stoull(decrypted_message_str, nullptr, 16));
    } else {
        std::cout << "Message: " << message_str << std::endl;
        std::cout << "Ciphertext: " << ciphertext_str << std::endl;
        std::cout << "Decrypted message: " << decrypted_message_str << std::endl;
    }

    // Clean up dynamically allocated memory
    delete[] n_str;
    delete[] e_str;
    delete[] d_str;
    delete[] ciphertext_str;
    delete[] decrypted_message_str;

    return 0;
}
