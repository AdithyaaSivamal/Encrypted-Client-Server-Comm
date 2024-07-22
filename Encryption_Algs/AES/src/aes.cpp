#include <iostream>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <string>
#include <cstdint>
#include "transformations.h"
#include "../key_expansion/key_expansion.h"

using namespace std;

/**
 * @brief Encrypts blocks of data using AES encryption.
 * 
 * @param blocks Blocks of data to encrypt.
 * @param roundKeys Round keys generated from the key expansion process.
 * @return vector<vector<uint8_t>> Encrypted blocks of data.
 */
vector<vector<uint8_t>> encrypt(vector<vector<uint8_t>>& blocks, const vector<vector<uint8_t>>& roundKeys) {
    vector<vector<uint8_t>> encryptedBlocks = blocks;

    for (auto& block : encryptedBlocks) {  
        xorWithRoundKey(block, roundKeys[0]); 
        subBytes(block);  
        shiftRows(block);  

        for (size_t i = 1; i < roundKeys.size() - 1; ++i) {  
            mixColumns(block);  
            xorWithRoundKey(block, roundKeys[i]);
            subBytes(block);  
            shiftRows(block); 
        }
        xorWithRoundKey(block, roundKeys.back()); 
    }
    return encryptedBlocks;  
}

/**
 * @brief Decrypts blocks of data using AES decryption.
 * 
 * @param blocks Blocks of data to decrypt.
 * @param roundKeys Round keys generated from the key expansion process.
 * @return vector<vector<uint8_t>> Decrypted blocks of data.
 */
vector<vector<uint8_t>> decrypt(const vector<vector<uint8_t>>& blocks, const vector<vector<uint8_t>>& roundKeys) {
    vector<vector<uint8_t>> decryptedBlocks = blocks;  

    for (auto& block : decryptedBlocks) {
        // Initial round key addition
        xorWithRoundKey(block, roundKeys[roundKeys.size() - 1]);

        for (int i = roundKeys.size() - 2; i > 0; --i) {
            inverseShiftRows(block);
            inverseSubBytes(block);
            xorWithRoundKey(block, roundKeys[i]);
            inverseMixColumns(block);  
        }

        // Last round skips Inverse MixColumns
        inverseShiftRows(block);
        inverseSubBytes(block);
        xorWithRoundKey(block, roundKeys[0]);
    }

    return decryptedBlocks;
}

// Expose AES encryption and decryption functions to be called from Python
extern "C" {

    /**
     * @brief Encrypts a plaintext using AES and a given key.
     * 
     * @param key The encryption key.
     * @param plaintext The plaintext to encrypt.
     * @param ciphertext The resulting ciphertext.
     */
    __declspec(dllexport) void encrypt(const unsigned char* key, const unsigned char* plaintext, unsigned char* ciphertext) {
        vector<uint8_t> keyVec;
        cout << "Received key: ";
        for (size_t i = 0; i < 16; ++i) {
            keyVec.push_back(static_cast<uint8_t>(key[i]));
            cout << hex << setw(2) << setfill('0') << (int)key[i] << " ";
        }
        cout << endl;

        auto roundKeys = keyExpansion(keyVec);

        vector<uint8_t> plaintextVec;
        cout << "Received plaintext: ";
        for (size_t i = 0; i < 16; ++i) {
            plaintextVec.push_back(static_cast<uint8_t>(plaintext[i]));
            cout << hex << setw(2) << setfill('0') << (int)plaintext[i] << " ";
        }
        cout << endl;

        auto blocks = groupBytesToBlocks(plaintextVec);
        auto encryptedBlocks = encrypt(blocks, roundKeys);

        // Flatten the encrypted blocks into a single array
        size_t idx = 0;
        for (const auto& block : encryptedBlocks) {
            for (const auto& byte : block) {
                ciphertext[idx++] = byte;
            }
        }
    }

    /**
     * @brief Decrypts a ciphertext using AES and a given key.
     * 
     * @param key The decryption key.
     * @param ciphertext The ciphertext to decrypt.
     * @param plaintext The resulting plaintext.
     */
    __declspec(dllexport) void decrypt(const unsigned char* key, const unsigned char* ciphertext, unsigned char* plaintext) {
        vector<uint8_t> keyVec;
        cout << "Received key: ";
        for (size_t i = 0; i < 16; ++i) {
            keyVec.push_back(static_cast<uint8_t>(key[i]));
            cout << hex << setw(2) << setfill('0') << (int)key[i] << " ";
        }
        cout << endl;

        auto roundKeys = keyExpansion(keyVec);

        vector<uint8_t> ciphertextVec;
        cout << "Received ciphertext: ";
        for (size_t i = 0; i < 16; ++i) {
            ciphertextVec.push_back(static_cast<uint8_t>(ciphertext[i]));
            cout << hex << setw(2) << setfill('0') << (int)ciphertext[i] << " ";
        }
        cout << endl;

        auto blocks = groupBytesToBlocks(ciphertextVec);
        auto decryptedBlocks = decrypt(blocks, roundKeys);

        // Flatten the decrypted blocks into a single array
        size_t idx = 0;
        for (const auto& block : decryptedBlocks) {
            for (const auto& byte : block) {
                plaintext[idx++] = byte;
            }
        }
    }
}

int main() {
    // Get plaintext from user
    cout << "Enter plaintext: ";
    string plaintext;
    getline(cin, plaintext);

    // Get key from user
    cout << "Enter 16-byte key in hexadecimal (32 hex characters): ";
    string hexKey;
    cin >> hexKey;

    // Convert hex key to byte vector
    vector<uint8_t> key;
    for (size_t i = 0; i < hexKey.length(); i += 2) {
        string byteString = hexKey.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(stoi(byteString, nullptr, 16));
        key.push_back(byte);
    }

    // Ensure the key is exactly 16 bytes
    if (key.size() != 16) {
        cerr << "Key must be exactly 16 bytes (32 hex characters)" << endl;
        return 1;
    }

    // Key expansion
    auto roundKeys = keyExpansion(key);

    // Plaintext processing
    vector<uint8_t> bytes = stringToBytes(plaintext);
    auto blocks = groupBytesToBlocks(bytes);

    // Print the plaintext and its corresponding blocks
    cout << endl;
    cout << "Plaintext: " << plaintext << endl;

    cout << "Blocks:" << endl;
    int block_count_1 = 1;
    for (const auto& block : blocks) {
        cout << "Block " << block_count_1 << ": ";
        for (const auto& byte : block) {
            cout << hex << setw(2) << setfill('0') << (int)byte << " ";
        }
        cout << endl;
        block_count_1++;
    }

    cout << endl;
    cout << "--------------------------------------------" << endl;
    cout << endl;

    // Encrypt the blocks
    auto encryptedBlocks = encrypt(blocks, roundKeys);

    // Print the encrypted blocks
    cout << "Encrypted Blocks:" << endl;
    int block_count_2 = 1;
    for (const auto& block : encryptedBlocks) {
        cout << "Block " << block_count_2 << ": ";
        for (const auto& byte : block) {
            cout << hex << setw(2) << setfill('0') << (int)byte << " ";
        }
        cout << endl;
        block_count_2++;
    }

    cout << endl;
    cout << "--------------------------------------------" << endl;
    cout << endl;

    // Decrypt the blocks
    auto decryptedBlocks = decrypt(encryptedBlocks, roundKeys);

    // Print the decrypted blocks
    cout << "\nDecrypted Blocks:" << endl;
    int block_count_3 = 1;
    for (const auto& block : decryptedBlocks) {
        cout << "Block " << block_count_3 << ": ";
        for (const auto& byte : block) {
            cout << hex << setw(2) << setfill('0') << (int)byte << " ";
        }
        cout << endl;
        block_count_3++;
    }

    // Convert decrypted blocks back to string and print
    cout << "Decrypted text: " << bytesToString(decryptedBlocks) << endl;
    cout << endl;

    return 0;
}
