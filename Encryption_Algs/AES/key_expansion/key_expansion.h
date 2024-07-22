#ifndef KEY_EXPANSION_H
#define KEY_EXPANSION_H

#include <vector>
#include <cstdint>

/**
 * Performs the AES key expansion.
 * @param key The original encryption key.
 * @return A 2D vector containing the expanded round keys.
 */
std::vector<std::vector<uint8_t>> keyExpansion(const std::vector<uint8_t>& key);

/**
 * Rotates the bytes in a word to the left.
 * @param word The word to be rotated.
 * @return A new word with the bytes rotated to the left.
 */
std::vector<uint8_t> rotWord(const std::vector<uint8_t>& word);

/**
 * Applies the SubBytes transformation to each byte in a word using the S-box.
 * @param word The word to be substituted.
 * @return A new word with the substituted bytes.
 */
std::vector<uint8_t> subWord(const std::vector<uint8_t>& word);

#endif
