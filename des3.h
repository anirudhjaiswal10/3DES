#ifndef DES3_H
#define DES3_H

#include <stdint.h>
#include <stdlib.h>

// DES Block and Key Sizes
#define DES_BLOCK_SIZE 8  // 64-bit block
#define DES_KEY_SIZE 8     // 64-bit key
#define DES3_KEY_SIZE 24   // 3DES requires 24 bytes (192-bit)

// DES Operation Modes
#define DES_ENCRYPT 1
#define DES_DECRYPT 0

// Structure for DES round keys (each subkey is 48 bits)
typedef struct {
    uint64_t subkeys[16];  // 16 subkeys, each derived from the main key
} DES_RoundKeys;

// Structure for 3DES keys (Extends DES Round Keys)
typedef struct {
    DES_RoundKeys roundKeys1;
    DES_RoundKeys roundKeys2;
    DES_RoundKeys roundKeys3;
    uint64_t key1;
    uint64_t key2;
    uint64_t key3;
} DES3_Keys;


// ================================
//      Key Schedule Functions
// ================================
void des_apply_permutation(uint64_t *output, uint64_t input, const uint8_t *table, int n);
void des_generate_round_keys(uint64_t key, DES_RoundKeys *round_keys);
void des_feistel_function(uint32_t right, uint64_t subkey, uint32_t *output);

// ================================
//      Block Encryption/Decryption
// ================================
void des_encrypt_block(const uint8_t *input, uint8_t *output, uint64_t key);
void des_decrypt_block(const uint8_t *input, uint8_t *output, uint64_t key);

// ================================
//      3DES Encryption/Decryption
// ================================
void des3_encrypt_block(const uint8_t *input, uint8_t *output, uint64_t key1, uint64_t key2, uint64_t key3);
void des3_decrypt_block(const uint8_t *input, uint8_t *output, uint64_t key1, uint64_t key2, uint64_t key3);

// ================================
//      CBC Mode Encryption/Decryption
// ================================

void des3_cbc_encrypt(uint8_t *data, size_t length, uint64_t key1, uint64_t key2, uint64_t key3, uint8_t iv[8]);
void des3_cbc_decrypt(uint8_t *data, size_t length, uint64_t key1, uint64_t key2, uint64_t key3, uint8_t iv[8]);

// ================================
//      Utility Functions
// ================================
void des_uint64_to_be_bytes(uint64_t value, uint8_t *bytes);
uint64_t des_be_bytes_to_uint64(const uint8_t *bytes);

// S-Boxes (8 substitution tables)
extern const uint32_t DES_SBOX1[];
extern const uint32_t DES_SBOX2[];
extern const uint32_t DES_SBOX3[];
extern const uint32_t DES_SBOX4[];
extern const uint32_t DES_SBOX5[];
extern const uint32_t DES_SBOX6[];
extern const uint32_t DES_SBOX7[];
extern const uint32_t DES_SBOX8[];

#endif // DES3_H
