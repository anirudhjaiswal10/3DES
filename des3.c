#include "des3.h"
#include <string.h>


// Permutation tables (in hexadecimal)
const uint8_t DES_INITIAL_KEY_PERMUTATION[] = {57, 49,  41, 33,  25,  17,  9,
    1, 58,  50, 42,  34,  26, 18,
   10,  2,  59, 51,  43,  35, 27,
   19, 11,   3, 60,  52,  44, 36,
   63, 55,  47, 39,  31,  23, 15,
    7, 62,  54, 46,  38,  30, 22,
   14,  6,  61, 53,  45,  37, 29,
   21, 13,   5, 28,  20,  12,  4};


const uint8_t DES_INITIAL_MESSAGE_PERMUTATION[] =  {58, 50, 42, 34, 26, 18, 10, 2,
                                                60, 52, 44, 36, 28, 20, 12, 4,
                                                62, 54, 46, 38, 30, 22, 14, 6,
                                                64, 56, 48, 40, 32, 24, 16, 8,
                                                57, 49, 41, 33, 25, 17,  9, 1,
                                                59, 51, 43, 35, 27, 19, 11, 3,
                                                61, 53, 45, 37, 29, 21, 13, 5,
                                                63, 55, 47, 39, 31, 23, 15, 7};

const uint8_t DES_KEY_SHIFT_SIZES[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};



    const uint8_t DES_SUB_KEY_PERMUTATION[]=  {14, 17, 11, 24,  1,  5,
                                         3, 28, 15,  6, 21, 10,
                                         23, 19, 12,  4, 26,  8,
                                         16,  7, 27, 20, 13,  2,
                                         41, 52, 31, 37, 47, 55,
                                         30, 40, 51, 45, 33, 48,
                                         44, 49, 39, 56, 34, 53,
                                         46, 42, 50, 36, 29, 32};

    const uint8_t DES_MESSAGE_EXPANSION[] = 
                   {32,  1,  2,  3,  4,  5,
					4,  5,  6,  7,  8,  9,
					8,  9, 10, 11, 12, 13,
					12, 13, 14, 15, 16, 17,
					16, 17, 18, 19, 20, 21,
					20, 21, 22, 23, 24, 25,
					24, 25, 26, 27, 28, 29,
					28, 29, 30, 31, 32,  1};

    const uint8_t DES_RIGHT_SUB_MESSAGE_PERMUTATION[] = {16,  7, 20, 21,
                                                 29, 12, 28, 17,
                                                 1, 15, 23, 26,
                                                 5, 18, 31, 10,
                                                 2,  8, 24, 14,
                                                 32, 27,  3,  9,
                                                 19, 13, 30,  6,
                                                 22, 11,  4, 25};
const uint8_t DES_FINAL_MESSAGE_PERMUTATION[] = {40,  8, 48, 16, 56, 24, 64, 32,
									          39,  7, 47, 15, 55, 23, 63, 31,
									          38,  6, 46, 14, 54, 22, 62, 30,
									          37,  5, 45, 13, 53, 21, 61, 29,
									          36,  4, 44, 12, 52, 20, 60, 28,
									          35,  3, 43, 11, 51, 19, 59, 27,
									          34,  2, 42, 10, 50, 18, 58, 26,
									          33,  1, 41,  9, 49, 17, 57, 25};

// S-boxes (in hexadecimal)
const uint32_t DES_SBOX1[] = {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
    0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
    4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
   15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13};

 const uint32_t DES_SBOX2[] = {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
    3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
    0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
   13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9};

const uint32_t DES_SBOX3[] = {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
    13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
    13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
     1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12};

const uint32_t DES_SBOX4[] = { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
    13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
    10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
     3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14};

 const uint32_t DES_SBOX5[]=  { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
     4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3};

 const uint32_t DES_SBOX6[] = {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
    10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
     9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
     4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13};

 const uint32_t DES_SBOX7[] =  { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
    13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
     1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
     6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12};


const uint32_t DES_SBOX8[] = {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
    1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
    7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
    2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11};

// ================================
//      Utility Functions
// ================================

void des_uint64_to_be_bytes(uint64_t value, uint8_t *bytes) {
    bytes[0] = (value >> 56) & 0xFF;
    bytes[1] = (value >> 48) & 0xFF;
    bytes[2] = (value >> 40) & 0xFF;
    bytes[3] = (value >> 32) & 0xFF;
    bytes[4] = (value >> 24) & 0xFF;
    bytes[5] = (value >> 16) & 0xFF;
    bytes[6] = (value >> 8) & 0xFF;
    bytes[7] = value & 0xFF;
}

uint64_t des_be_bytes_to_uint64(const uint8_t *bytes) {
    return ((uint64_t)bytes[0] << 56) | ((uint64_t)bytes[1] << 48) |
           ((uint64_t)bytes[2] << 40) | ((uint64_t)bytes[3] << 32) |
           ((uint64_t)bytes[4] << 24) | ((uint64_t)bytes[5] << 16) |
           ((uint64_t)bytes[6] << 8) | (uint64_t)bytes[7];
}

// ================================
//      Permutation Function
// ================================

void des_apply_permutation(uint64_t *output, uint64_t input, const uint8_t *table, int n) {
    uint64_t result = 0;
    for (int i = 0; i < n; i += 4) {
        result |= (((input >> (64 - table[i])) & 1) << (n - 1 - i)) |
                  (((input >> (64 - table[i+1])) & 1) << (n - 2 - i)) |
                  (((input >> (64 - table[i+2])) & 1) << (n - 3 - i)) |
                  (((input >> (64 - table[i+3])) & 1) << (n - 4 - i));
    }
    *output = result;
}

// ================================
//      Key Scheduling
// ================================

void des_generate_round_keys(uint64_t key, DES_RoundKeys *round_keys) {
    uint64_t permuted_key;
    des_apply_permutation(&permuted_key, key, DES_INITIAL_KEY_PERMUTATION, 56);

    uint32_t left = (permuted_key >> 28) & 0x0FFFFFFF;
    uint32_t right = permuted_key & 0x0FFFFFFF;

    for (int i = 0; i < 16; i++) {
        left = ((left << DES_KEY_SHIFT_SIZES[i]) | (left >> (28 - DES_KEY_SHIFT_SIZES[i]))) & 0x0FFFFFFF;
        right = ((right << DES_KEY_SHIFT_SIZES[i]) | (right >> (28 - DES_KEY_SHIFT_SIZES[i]))) & 0x0FFFFFFF;
        des_apply_permutation(&round_keys->subkeys[i], ((uint64_t)left << 28) | right, DES_SUB_KEY_PERMUTATION, 48);
    }
}

// ================================
//      Feistel Function
// ================================

void des_feistel_function(uint32_t right, uint64_t subkey, uint32_t *output) {
    uint64_t expanded;
    des_apply_permutation(&expanded, right, DES_MESSAGE_EXPANSION, 48);
    expanded ^= subkey;

    uint32_t substituted = 0;
    for (int i = 0; i < 8; i += 2) {
        uint8_t row1 = ((expanded >> (42 - (i * 6))) & 0x20) | ((expanded >> (42 - (i * 6 - 5))) & 0x01);
        uint8_t col1 = (expanded >> (43 - (i * 6 - 4))) & 0x0F;
        uint8_t row2 = ((expanded >> (42 - ((i+1) * 6))) & 0x20) | ((expanded >> (42 - ((i+1) * 6 - 5))) & 0x01);
        uint8_t col2 = (expanded >> (43 - ((i+1) * 6 - 4))) & 0x0F;
        substituted |= ((&DES_SBOX1[i])[row1 * 16 + col1] << (28 - (i * 4))) |
                       ((&DES_SBOX1[i+1])[row2 * 16 + col2] << (28 - ((i+1) * 4)));
    }

    des_apply_permutation((uint64_t *)output, substituted, DES_RIGHT_SUB_MESSAGE_PERMUTATION, 32);
}

// ================================
//      DES Block Encryption with Loop Unrolling
// ================================
void des_encrypt_block(const uint8_t *input, uint8_t *output, uint64_t key) {
    uint64_t data = des_be_bytes_to_uint64(input);
    uint64_t permuted;
    des_apply_permutation(&permuted, data, DES_INITIAL_MESSAGE_PERMUTATION, 64);

    uint32_t left = (permuted >> 32) & 0xFFFFFFFF;
    uint32_t right = permuted & 0xFFFFFFFF;

    DES_RoundKeys round_keys;
    des_generate_round_keys(key, &round_keys);

    // Unroll the Feistel network loop (16 rounds)
    for (int i = 0; i < 16; i += 2) {
        uint32_t temp = right;
        des_feistel_function(right, round_keys.subkeys[i], &right);
        right ^= left;
        left = temp;

        temp = right;
        des_feistel_function(right, round_keys.subkeys[i + 1], &right);
        right ^= left;
        left = temp;
    }

    uint64_t final = ((uint64_t)right << 32) | left;
    des_apply_permutation(&data, final, DES_FINAL_MESSAGE_PERMUTATION, 64);
    des_uint64_to_be_bytes(data, output);
}

// ================================
//      DES Block Decryption with Loop Unrolling
// ================================
void des_decrypt_block(const uint8_t *input, uint8_t *output, uint64_t key) {
    uint64_t data = des_be_bytes_to_uint64(input);
    uint64_t permuted;
    des_apply_permutation(&permuted, data, DES_INITIAL_MESSAGE_PERMUTATION, 64);

    uint32_t left = (permuted >> 32) & 0xFFFFFFFF;
    uint32_t right = permuted & 0xFFFFFFFF;

    DES_RoundKeys round_keys;
    des_generate_round_keys(key, &round_keys);

    // Unroll the Feistel network loop (16 rounds in reverse)
    for (int i = 15; i >= 0; i -= 2) {
        uint32_t temp = right;
        des_feistel_function(right, round_keys.subkeys[i], &right);
        right ^= left;
        left = temp;

        temp = right;
        des_feistel_function(right, round_keys.subkeys[i - 1], &right);
        right ^= left;
        left = temp;
    }

    uint64_t final = ((uint64_t)right << 32) | left;
    des_apply_permutation(&data, final, DES_FINAL_MESSAGE_PERMUTATION, 64);
    des_uint64_to_be_bytes(data, output);
}

// ================================
//      3DES Block Encryption with Loop Unrolling
// ================================
void des3_encrypt_block(const uint8_t *input, uint8_t *output, uint64_t key1, uint64_t key2, uint64_t key3) {
    uint8_t block[8];

    // First DES encryption
    des_encrypt_block(input, block, key1);

    // DES decryption
    des_decrypt_block(block, block, key2);

    // Final DES encryption
    des_encrypt_block(block, output, key3);
}

// ================================
//      3DES Block Decryption with Loop Unrolling
// ================================
void des3_decrypt_block(const uint8_t *input, uint8_t *output, uint64_t key1, uint64_t key2, uint64_t key3) {
    uint8_t block[8];

    // First DES decryption
    des_decrypt_block(input, block, key3);

    // DES encryption
    des_encrypt_block(block, block, key2);

    // Final DES decryption
    des_decrypt_block(block, output, key1);
}

// ================================
//      Optimized 3DES CBC Encryption with Loop Unrolling
// ================================
void des3_cbc_encrypt(uint8_t *data, size_t length, uint64_t key1, uint64_t key2, uint64_t key3, uint8_t iv[8]) {
    size_t i = 0;
    
    while (i < length) {
        uint8_t *block = &data[i];

        // Unrolled XOR operation (8 bytes at a time)
        block[0] ^= iv[0]; block[1] ^= iv[1]; block[2] ^= iv[2]; block[3] ^= iv[3];
        block[4] ^= iv[4]; block[5] ^= iv[5]; block[6] ^= iv[6]; block[7] ^= iv[7];

        // Perform 3DES encryption on the block
        des3_encrypt_block(block, iv, key1, key2, key3);

        // Store the result directly in the data buffer
        memcpy(block, iv, 8);

        i += 8;
    }
}

// ================================
//      Optimized 3DES CBC Decryption with Loop Unrolling
// ================================
void des3_cbc_decrypt(uint8_t *data, size_t length, uint64_t key1, uint64_t key2, uint64_t key3, uint8_t iv[8]) {
    size_t i = 0;
    uint8_t prev_ciphertext[8];
    
    memcpy(prev_ciphertext, iv, 8);

    while (i < length) {
        uint8_t *block = &data[i];
        uint8_t current_ciphertext[8];

        // Save the current ciphertext before decryption
        memcpy(current_ciphertext, block, 8);

        // Perform 3DES decryption on the block
        des3_decrypt_block(block, block, key1, key2, key3);

        // Unrolled XOR operation (8 bytes at a time)
        block[0] ^= prev_ciphertext[0]; block[1] ^= prev_ciphertext[1];
        block[2] ^= prev_ciphertext[2]; block[3] ^= prev_ciphertext[3];
        block[4] ^= prev_ciphertext[4]; block[5] ^= prev_ciphertext[5];
        block[6] ^= prev_ciphertext[6]; block[7] ^= prev_ciphertext[7];

        // Update the previous ciphertext for the next block
        memcpy(prev_ciphertext, current_ciphertext, 8);

        i += 8;
    }
}