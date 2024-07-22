#ifndef HELPERFUNCTIONS_H
#define HELPERFUNCTIONS_H

#include <iostream>
#include <vector>
#include <ctime>
#include <cstdlib>
#include <cmath>
#include <numeric>
#include <stdexcept>
#include <string>
#include <gmp.h>

// Basic math functions
// Basic math functions
bool isPrime(int n);
int generatePrime();
int gcd(int a, int b);

// RSA functions
void modInverse(mpz_t result, const mpz_t a, const mpz_t m);
int gcd(int a, int b);
void generateLargePrime(mpz_t prime, gmp_randstate_t state, int bits);
void initializeRandomState(gmp_randstate_t state);

// Display functions
void displayEnhancedOutput(unsigned long long message, unsigned long long intMessage, int p, int q, unsigned long long n, unsigned long long phi, unsigned long long e, unsigned long long d, unsigned long long ciphertext, unsigned long long decryptedMessage);
std::string intToHex(int number);

#endif // FUNCTIONS_H
