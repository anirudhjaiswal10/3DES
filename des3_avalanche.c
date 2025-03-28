#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "des3.h"

#ifdef _WIN32
#include <windows.h>
double get_time() {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart / freq.QuadPart;
}
#else
#include <sys/time.h>
double get_time() {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + (t.tv_nsec / 1e9);
}
#endif

#define ITERATIONS 10
#define BLOCK_SIZE 8      // DES block size in bytes
#define TOTAL_BITS (BLOCK_SIZE * 8) // 64 bits in a block

// Function to count differing bits between two blocks
int count_bit_flips(const uint8_t *original, const uint8_t *modified, size_t size) {
    int count = 0;
    for (size_t i = 0; i < size; i++) {
        uint8_t diff = original[i] ^ modified[i];
        while (diff) {
            count += diff & 1;
            diff >>= 1;
        }
    }
    return count;
}

void test_avalanche_effect(uint64_t key1, uint64_t key2, uint64_t key3) {
    FILE *fp = fopen("avalanche_output.txt", "w");
    if (!fp) {
        fprintf(stderr, "Error opening file for writing.\n");
        return;
    }

    uint8_t plaintext[8] = {0x21, 0x38, 0xA9, 0xB4, 0x65, 0x7C, 0xED, 0xF0};
    uint8_t encrypted[8], modified_encrypted[8], iv[8];
    double total_avalanche = 0;

    // Initial IV
    uint8_t iv_init[8] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};

    // Iterate over 10 times, and flip one bit (always the same bit) per iteration
    for (int i = 0; i < ITERATIONS; i++) {
        // Update IV for each iteration
        uint8_t iv_new[8];
        for (int j = 0; j < 8; j++) {
            iv_new[j] = iv_init[j] ^ (i * 0x11); // This changes the IV each time
        }
        memcpy(iv, iv_new, 8); // Apply the updated IV

        // Encrypt the original plaintext with the updated IV
        uint8_t temp_plaintext[8];
        memcpy(temp_plaintext, plaintext, 8);
        des3_cbc_encrypt(temp_plaintext, 8, key1, key2, key3, iv);
        memcpy(encrypted, temp_plaintext, 8);

        // Flip one bit in the plaintext (bit 1 is chosen for flipping, i.e., the second bit)
        int bit_to_flip = 1; // Chosen bit to flip (0-63)
        uint8_t modified_plaintext[8];
        memcpy(modified_plaintext, plaintext, 8);
        modified_plaintext[bit_to_flip / 8] ^= (1 << (bit_to_flip % 8));  // Flip the bit

        // Encrypt the modified plaintext with the updated IV
        des3_cbc_encrypt(modified_plaintext, 8, key1, key2, key3, iv);
        memcpy(modified_encrypted, modified_plaintext, 8);

        // Calculate the Hamming distance between original and modified ciphertext
        int flipped_bits = count_bit_flips(encrypted, modified_encrypted, 8);
        double avalanche_percentage = (double)flipped_bits / TOTAL_BITS * 100;
        total_avalanche += avalanche_percentage;

        // Print the results for this iteration
        fprintf(fp, "Iteration %d:\n", i + 1);
        fprintf(fp, "Original Plaintext: ");
        for (int j = 0; j < 8; j++) fprintf(fp, "%02X ", plaintext[j]);
        fprintf(fp, "\nOriginal IV: ");
        for (int j = 0; j < 8; j++) fprintf(fp, "%02X ", iv_new[j]);
        fprintf(fp, "\nOriginal Ciphertext: ");
        for (int j = 0; j < 8; j++) fprintf(fp, "%02X ", encrypted[j]);
        fprintf(fp, "\nFlipping bit: %d\n", bit_to_flip);
        
        fprintf(fp, "Modified Plaintext (Flipped Bit %d): ", bit_to_flip);
        for (int j = 0; j < 8; j++) fprintf(fp, "%02X ", modified_plaintext[j]);
        fprintf(fp, "\nModified Ciphertext: ");
        for (int j = 0; j < 8; j++) fprintf(fp, "%02X ", modified_encrypted[j]);
        fprintf(fp, "\nHamming Distance: %d\n", flipped_bits);
        fprintf(fp, "Avalanche Effect: %.2f%%\n", avalanche_percentage);
    }

    double average_avalanche = total_avalanche / ITERATIONS;
    fprintf(fp, "\nFinal Average Avalanche Effect: %.2f%%\n", average_avalanche);

    fclose(fp);
    printf("\nFinal Average Avalanche Effect: %.2f%%\n", average_avalanche);
}

int main() {
    printf("Starting 3DES Avalanche Effect Test...\n");
    fflush(stdout);

    srand(time(NULL));

    // Initialize 3DES keys
    uint64_t key1 = 0x133457799BBCDFF1;
    uint64_t key2 = 0x1122334455667788;
    uint64_t key3 = 0xAABB09182736CCDD;

    test_avalanche_effect(key1, key2, key3);

    printf("3DES Avalanche Test Completed!\n");
    fflush(stdout);
    return 0;  
}