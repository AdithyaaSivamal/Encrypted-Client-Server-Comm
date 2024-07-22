#ifndef TRANSFORMATIONS_H
#define TRANSFORMATIONS_H

#include <iostream>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <string>

using namespace std;

// Constants
extern const uint8_t sBox[256];       // Substitution box for SubBytes step
extern const uint8_t invSBox[256];    // Inverse substitution box for InverseSubBytes step
extern const uint8_t rcon[10];        // Round constants for Key Expansion
extern const uint8_t mul2[256];       // Multiplication by 2 in GF(2^8) for MixColumns
extern const uint8_t mul3[256];       // Multiplication by 3 in GF(2^8) for MixColumns
extern const uint8_t mul9[256];       // Multiplication by 9 in GF(2^8) for Inverse MixColumns
extern const uint8_t mul11[256];      // Multiplication by 11 in GF(2^8) for Inverse MixColumns
extern const uint8_t mul13[256];      // Multiplication by 13 in GF(2^8) for Inverse MixColumns
extern const uint8_t mul14[256];      // Multiplication by 14 in GF(2^8) for Inverse MixColumns

// Helper Functions

/**
 * Converts a string to a vector of bytes and pads it to a multiple of 16 bytes.
 * @param text The input string to be converted.
 * @return A vector of bytes representing the padded input string.
 */
vector<uint8_t> stringToBytes(const string& text);

/**
 * Converts a 2D vector of bytes to a string.
 * @param byteBlocks The 2D vector of bytes.
 * @return A string representation of the byte blocks.
 */
string bytesToString(const vector<vector<uint8_t>>& byteBlocks);

/**
 * Groups a flat vector of bytes into 16-byte blocks.
 * @param bytes The input vector of bytes.
 * @return A 2D vector of 16-byte blocks.
 */
vector<vector<uint8_t>> groupBytesToBlocks(const vector<uint8_t>& bytes);

// Encryption functions

/**
 * XORs a block with a round key.
 * @param block The data block to be XORed.
 * @param roundKey The round key to XOR with the block.
 */
void xorWithRoundKey(vector<uint8_t>& block, const vector<uint8_t>& roundKey);

/**
 * Applies the SubBytes transformation using the S-box.
 * @param block The data block to be transformed.
 */
void subBytes(vector<uint8_t>& block);

/**
 * Applies the ShiftRows transformation to the block.
 * @param block The data block to be transformed.
 */
void shiftRows(vector<uint8_t>& block);

/**
 * Applies the MixColumns transformation to the block.
 * @param block The data block to be transformed.
 */
void mixColumns(vector<uint8_t>& block);

// Decryption functions

/**
 * Applies the InverseShiftRows transformation to the block.
 * @param block The data block to be transformed.
 */
void inverseShiftRows(vector<uint8_t>& block);

/**
 * Applies the Inverse SubBytes transformation using the inverse S-box.
 * @param block The data block to be transformed.
 */
void inverseSubBytes(vector<uint8_t>& block);

/**
 * Applies the Inverse MixColumns transformation to the block.
 * @param block The data block to be transformed.
 */
void inverseMixColumns(vector<uint8_t>& block);

#endif
