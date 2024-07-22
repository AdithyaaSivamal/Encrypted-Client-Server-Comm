#include <iostream>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <string>
#include "../src/transformations.h"

using namespace std;

/**
 * @brief Rotates a 4-byte word to the left.
 * 
 * @param word A vector of 4 bytes to be rotated.
 * @return A vector of 4 bytes after rotation.
 */
vector<uint8_t> rotWord(const vector<uint8_t>& word) {
    vector<uint8_t> rotated = {word[1], word[2], word[3], word[0]};
    return rotated;
}

/**
 * @brief Applies the SubBytes transformation to a 4-byte word.
 * 
 * @param word A vector of 4 bytes to be transformed.
 * @return A vector of 4 bytes after SubBytes transformation.
 */
vector<uint8_t> subWord(const vector<uint8_t>& word) {
    vector<uint8_t> result(4);
    for (int i = 0; i < 4; ++i) {
        result[i] = sBox[word[i]];
    }
    return result;
}

/**
 * @brief Expands a cipher key into a series of round keys.
 * 
 * @param key A vector of bytes representing the cipher key.
 * @return A vector of vectors, where each inner vector is a round key.
 */
vector<vector<uint8_t>> keyExpansion(const vector<uint8_t>& key) {
    int Nk = key.size() / 4; // Number of 32-bit words in the key
    int Nr = Nk + 6;         // Number of rounds
    int Nb = 4;              // Block size in 32-bit words
    vector<vector<uint8_t>> w(Nb * (Nr + 1), vector<uint8_t>(4));

    // Copy the original key to the first Nk words of w
    for (int i = 0; i < Nk; ++i) {
        w[i] = {key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]};
    }

    vector<uint8_t> temp(4);
    for (int i = Nk; i < Nb * (Nr + 1); ++i) {
        temp = w[i - 1];
        if (i % Nk == 0) {
            temp = subWord(rotWord(temp));
            temp[0] ^= rcon[i / Nk - 1];
        } else if (Nk > 6 && i % Nk == 4) {
            temp = subWord(temp);  // Only for AES-256
        }

        for (int j = 0; j < 4; ++j) {
            w[i][j] = w[i - Nk][j] ^ temp[j];
        }
    }

    // Extract round keys from w
    vector<vector<uint8_t>> roundKeys;
    for (int i = 0; i < (Nr + 1); ++i) {
        vector<uint8_t> roundKey;
        for (int j = 0; j < 4; ++j) {
            roundKey.insert(roundKey.end(), w[4 * i + j].begin(), w[4 * i + j].end());
        }
        roundKeys.push_back(roundKey);
    }

    return roundKeys;
}
