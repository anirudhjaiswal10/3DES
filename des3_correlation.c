#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "des3.h"  // Make sure this includes 3DES CBC functions

#define BLOCK_SIZE 8   // DES block size in bytes (for simplicity, adjusting 3DES to use 8 bytes here)
#define SAMPLE_SIZE 10 // Number of iterations for correlation test

// Function to compute correlation coefficient
double compute_correlation(const uint8_t *plaintext, const uint8_t *ciphertext, size_t length) {
    double sum_plain = 0, sum_cipher = 0, sum_plain_cipher = 0;
    double sum_plain_sq = 0, sum_cipher_sq = 0;
    int n = length * 8;  // Total number of bits

    // Calculate correlation between plaintext and ciphertext bit-by-bit
    for (size_t i = 0; i < length; i++) {
        for (int bit = 0; bit < 8; bit++) {
            int p_bit = (plaintext[i] >> bit) & 1;  // Extract the bit from the plaintext
            int c_bit = (ciphertext[i] >> bit) & 1; // Extract the bit from the ciphertext

            sum_plain += p_bit;
            sum_cipher += c_bit;
            sum_plain_cipher += p_bit * c_bit;
            sum_plain_sq += p_bit * p_bit;
            sum_cipher_sq += c_bit * c_bit;
        }
    }

    // Compute the Pearson correlation coefficient
    double numerator = (n * sum_plain_cipher) - (sum_plain * sum_cipher);
    double denominator = sqrt((n * sum_plain_sq - sum_plain * sum_plain) * (n * sum_cipher_sq - sum_cipher * sum_cipher));

    // Return the correlation coefficient, checking for division by zero
    return (denominator == 0) ? 0 : (numerator / denominator);
}

// 3DES encryption function in CBC mode (simplified version for 8-byte blocks)
void des3_encrypt_cbc(const uint8_t *input, uint8_t *output, uint64_t key1, uint64_t key2, uint64_t key3, uint8_t *iv) {
    uint8_t block[BLOCK_SIZE];
    uint8_t previous_ciphertext[BLOCK_SIZE];

    // Copy the IV to initialize the previous ciphertext (used in CBC mode)
    memcpy(previous_ciphertext, iv, BLOCK_SIZE);

    // XOR the plaintext with the previous ciphertext (or IV for the first block)
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] = input[i] ^ previous_ciphertext[i];
    }

    // Perform 3DES encryption in CBC mode with 3 keys
    des3_cbc_encrypt(block, BLOCK_SIZE, key1, key2, key3, iv);

    // Store the output ciphertext and update previous ciphertext for next block
    memcpy(output, block, BLOCK_SIZE);
    memcpy(previous_ciphertext, output, BLOCK_SIZE);  // Update the previous ciphertext for chaining
}

// Function to run the correlation test and write results to a file
void test_correlation(uint64_t key1, uint64_t key2, uint64_t key3) {
    srand(time(NULL));  // Seed the random number generator
    FILE *file = fopen("correlation_results_3des.txt", "w");
    if (file == NULL) {
        printf("Error opening file!\n");
        return;
    }

    fprintf(file, "=== 3DES CBC Mode Correlation Results ===\n");

    double total_correlation = 0.0;  // Variable to accumulate correlation for all iterations

    for (int i = 0; i < SAMPLE_SIZE; i++) {
        uint8_t plaintext[BLOCK_SIZE], ciphertext[BLOCK_SIZE], iv[BLOCK_SIZE];

        // Generate random plaintext and IV for each iteration
        for (int j = 0; j < BLOCK_SIZE; j++) {
            plaintext[j] = rand() % 256;
            iv[j] = rand() % 256;  // Random IV to ensure unpredictability
        }

        // Perform encryption in CBC mode with the random IV
        des3_encrypt_cbc(plaintext, ciphertext, key1, key2, key3, iv);

        // Compute the correlation between plaintext and ciphertext
        double correlation = compute_correlation(plaintext, ciphertext, BLOCK_SIZE);
        total_correlation += correlation;

        // Write the plaintext, ciphertext, and correlation to the file for this iteration
        fprintf(file, "Iteration %d:\n", i + 1);
        fprintf(file, "Plaintext: ");
        for (int j = 0; j < BLOCK_SIZE; j++) {
            fprintf(file, "%02X", plaintext[j]);
        }
        fprintf(file, "\nCiphertext: ");
        for (int j = 0; j < BLOCK_SIZE; j++) {
            fprintf(file, "%02X", ciphertext[j]);
        }
        fprintf(file, "\nCorrelation: %.6f\n\n", correlation);
    }

    // Print the overall average correlation to the file
    double avg_correlation = total_correlation / SAMPLE_SIZE;
    double correlation_percentage = fabs(avg_correlation) * 100;
    fprintf(file, "\n=== Overall Correlation Result ===\n");
    fprintf(file, "Average Correlation: %.6f\n", avg_correlation);
    fprintf(file, "Correlation Effect: %.2f%%\n", correlation_percentage);

    fclose(file);  // Close the file
}

int main() {
    uint64_t key1 = 0x133457799BBCDFF1;  // Example key1
    uint64_t key2 = 0x1122334455667788;  // Example key2
    uint64_t key3 = 0xAABB09182736CCDD;  // Example key3
    test_correlation(key1, key2, key3);  // Run the correlation test with the given keys
    return 0;
}
