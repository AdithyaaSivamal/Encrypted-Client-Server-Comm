#include <iostream>
#include <vector>
#include <ctime>
#include <cstdlib>
#include <cmath>
#include <numeric>
#include <stdexcept>
#include <string>
#include <sstream>
#include <gmp.h>
#include <windows.h>
#include "helperFunctions.h"

/**
 * @brief Check if a number is prime.
 * 
 * @param n The number to check.
 * @return true if the number is prime, false otherwise.
 */
bool isPrime(int n) {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    for (int i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return false;
    }
    return true;
}

/**
 * @brief Generate a random prime number within a specified range.
 * 
 * @return int The generated prime number.
 */
int generatePrime() {
    int prime;
    do {
        prime = rand() % 100 + 100; // Adjust range for larger primes
    } while (!isPrime(prime));
    return prime;
}

/**
 * @brief Calculate the greatest common divisor (GCD) of two numbers.
 * 
 * @param a First number.
 * @param b Second number.
 * @return int The GCD of the two numbers.
 */
int gcd(int a, int b) {
    while (b != 0) {
        int t = b;
        b = a % b;
        a = t;
    }
    return a;
}

/**
 * @brief Calculate the modular inverse of a number.
 * 
 * @param result The result of the modular inverse calculation.
 * @param a The number to find the modular inverse of.
 * @param m The modulus.
 */
void modInverse(mpz_t result, const mpz_t a, const mpz_t m) {
    mpz_t t, newT, r, newR, quotient, temp;
    mpz_inits(t, newT, r, newR, quotient, temp, nullptr);

    mpz_set_ui(t, 0);
    mpz_set_ui(newT, 1);
    mpz_set(r, m);
    mpz_set(newR, a);

    while (mpz_cmp_ui(newR, 0) != 0) {
        mpz_fdiv_q(quotient, r, newR);

        mpz_set(temp, newT);
        mpz_mul(newT, quotient, newT);
        mpz_sub(newT, t, newT);
        mpz_set(t, temp);

        mpz_set(temp, newR);
        mpz_mul(newR, quotient, newR);
        mpz_sub(newR, r, newR);
        mpz_set(r, temp);
    }

    if (mpz_cmp_ui(r, 1) > 0) {
        std::cerr << "Error: a is not invertible\n";
    } else {
        if (mpz_cmp_ui(t, 0) < 0) {
            mpz_add(t, t, m);
        }
        mpz_set(result, t);
    }

    mpz_clears(t, newT, r, newR, quotient, temp, nullptr);
}

/**
 * @brief Initialize the GMP random state with a seed from the Windows cryptographic provider.
 * 
 * @param state The GMP random state to initialize.
 */
void initializeRandomState(gmp_randstate_t state) {
    unsigned long seed;
    HCRYPTPROV hProvider = 0;

    if (!CryptAcquireContext(&hProvider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        throw std::runtime_error("Error: Could not acquire cryptographic provider.");
    }

    if (!CryptGenRandom(hProvider, sizeof(seed), reinterpret_cast<BYTE*>(&seed))) {
        CryptReleaseContext(hProvider, 0);
        throw std::runtime_error("Error: Could not generate random seed.");
    }

    CryptReleaseContext(hProvider, 0);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, seed);
}

/**
 * @brief Generate a large prime number with a specified number of bits.
 * 
 * @param prime The generated prime number.
 * @param state The GMP random state to use.
 * @param bits The number of bits for the prime number.
 */
void generateLargePrime(mpz_t prime, gmp_randstate_t state, int bits) {
    mpz_rrandomb(prime, state, bits);
    mpz_nextprime(prime, prime);
}

/**
 * @brief Display detailed output of the RSA process.
 * 
 * @param message The original message.
 * @param intMessage The integer representation of the message.
 * @param p Prime number p.
 * @param q Prime number q.
 * @param n The modulus n (product of p and q).
 * @param phi Euler's Totient function value.
 * @param e The public exponent e.
 * @param d The private exponent d.
 * @param ciphertext The encrypted message.
 * @param decryptedMessage The decrypted message.
 */
void displayEnhancedOutput(unsigned long long message, unsigned long long intMessage, int p, int q, unsigned long long n, unsigned long long phi, unsigned long long e, unsigned long long d, unsigned long long ciphertext, unsigned long long decryptedMessage) {
    unsigned long long digitCount = std::log10(e) + 1;
    const std::string blue = "\033[34m";
    const std::string reset = "\033[0m";

    std::cout << R"(
    ____  _____ ___ 
   / __ \/ ___//   |
  / /_/ /\__ \/ /| |
 / _, _/___/ / ___ |
/_/ |_|/____/_/  |_|
                    
----------------------------------
NOTE: This is an oversimplified RSA encryption and decryption demo. 
      It is not secure for production use. At all.
----------------------------------

)";
    std::cout << "Message = " << std::hex << message << std::endl;
    // Convert message to display int using
    std::cout << "Message as int = " << std::to_string(intMessage) << std::endl;
    std::cout << "-------------------------------\n\n";

    // Graph
    std::cout << "     Generate Prime numbers:" << std::endl;
    std::cout << "     " << blue << "p" << reset << " = " << std::dec << p << " ------- " << blue << "q" << reset << " = " << std::dec << q << "" << std::endl;
    std::cout << "                |" << std::endl;
    std::cout << "                |                             __" << std::endl;
    std::cout << "                |--> " << blue << "n" << reset << " = " << n << "                  |" << std::endl;
    std::cout << "           /    |                               |" << std::endl;
    std::cout << "           \\    |--> " << blue << "phi" << reset << " = (" << p << "-1) x (" << q << "-1)    |- " << blue << "d" << reset << " = e^(phi(n))^-1 (mod n)" << std::endl; 
    std::cout << "            \\   |                               |       |" << std::endl;
    if(digitCount == 4){
        std::cout << "            /\\  |--> " << blue << "e" << reset << " = " << e << ", a coprime of phi |       |" << std::endl;
    } else {
        std::cout << "            /\\  |--> " << blue << "e" << reset << " = " << e << ", a coprime of phi|       |" << std::endl;
    }
    std::cout << "           /  \\                               __|       |" << std::endl;
    std::cout << "          /    \\/                                       |" << std::endl;
    std::cout << "         /                                              V" << std::endl;
    std::cout << "encrypt() = (message)^e mod(n)          decrypt() = (ciphertext)^d mod(n)" << std::endl;
    std::cout << "message: " << std::hex << message << "                            ciphertext: " << std::hex << ciphertext << std::endl;
    std::cout << "  |                                                     |" << std::endl;
    std::cout << "  v                                                     v" << std::endl;
    std::cout << "message as int: " << std::to_string(intMessage) << "                    ciphertext as int: " << std::to_string(ciphertext) << std::endl;
    std::cout << "  |                                                     |" << std::endl;
    std::cout << "  v                                                     v" << std::endl;
    std::cout << "encrypted message: " << std::to_string(ciphertext) << "               decrypted message: " << std::to_string(decryptedMessage) << std::endl;
    std::cout << "  |                                                     |" << std::endl;
    std::cout << "  v                                                     V" << std::endl;
    std::cout << "encrypted message(in hex): " << std::hex << ciphertext << "           decrypted message(in hex): " << std::hex << decryptedMessage << std::endl;
    std::cout << std::endl;
    std::cout << "-------------------------------\n\n";
    std::cout << "Public key (e, n): (" << std::to_string(e) << ", " << std::to_string(n) << ")\n";
    std::cout << "Private key (d, n): (" << d << ", " << std::to_string(n) << ")\n";
    std::cout << "-------------------------------\n\n";
    std::cout << std::endl;
}

/**
 * @brief Convert an integer to its hexadecimal string representation.
 * 
 * @param number The integer to convert.
 * @return std::string The hexadecimal string representation of the number.
 */
std::string intToHex(int number) {
    std::stringstream ss;
    ss << std::hex << number;
    return ss.str();
}
