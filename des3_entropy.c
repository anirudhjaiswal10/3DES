#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "des3.h"

#define TEST_CASES 10 // Iterating 10 times for accuracy

// Function to compute Shannon entropy
double compute_entropy(const uint8_t *data, size_t size) {
    int freq[256] = {0};
    for (size_t i = 0; i < size; i++) {
        freq[data[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

// Function to compute 3DES CBC entropy
double compute_des3_cbc_entropy(size_t data_size, uint64_t key1, uint64_t key2, uint64_t key3) {
    double total_entropy = 0;
    uint8_t *data = (uint8_t *)malloc(data_size);
    uint8_t *encrypted_data = (uint8_t *)malloc(data_size);
    uint8_t iv[16] = {0};

    if (!data || !encrypted_data) {
        fprintf(stderr, "Memory allocation failed!\n");
        exit(1);
    }

    for (int test = 0; test < TEST_CASES; test++) {
        // Generate random data
        for (size_t i = 0; i < data_size; i++) {
            data[i] = rand() & 0xFF;
        }

        memset(iv, 0, 16); // Initialize IV to 0
        des3_cbc_encrypt(data, data_size, key1, key2, key3, iv); // Encrypt the data using 3DES CBC mode
        memcpy(encrypted_data, data, data_size); // Store the encrypted data

        // Calculate and accumulate entropy
        total_entropy += compute_entropy(encrypted_data, data_size);
    }

    free(data);
    free(encrypted_data);

    // Return the average entropy over all tests
    return total_entropy / TEST_CASES;
}

int main() {
    srand(time(NULL));
    uint64_t key1 = 0x133457799BBCDFF1;
    uint64_t key2 = 0x1122334455667788;
    uint64_t key3 = 0xAABB09182736CCDD;

    // Data sizes in bytes
    size_t data_sizes[] = {8, 16, 50, 200, 500, 1024, 100 * 1024, 250 * 1024, 500 * 1024, 750 * 1024, 1024 * 1024};
    const char *size_labels[] = {"8B", "16B", "50B", "200B", "500B", "1KB", "100KB", "250KB", "500KB", "750KB", "1MB"};

    // Open the CSV file to write results
    FILE *csv_file = fopen("des3_cbc_entropy_results.csv", "w");
    if (!csv_file) {
        fprintf(stderr, "Failed to open CSV file for writing.\n");
        return 1;
    }

    // Write the header row
    fprintf(csv_file, "Data Size (Bytes),Average Entropy (bits/byte)\n");

    // Loop through each data size and compute entropy, then write to CSV
    for (int i = 0; i < sizeof(data_sizes) / sizeof(data_sizes[0]); i++) {
        printf("Processing %s...\n", size_labels[i]);  // Display progress
        double avg_entropy = compute_des3_cbc_entropy(data_sizes[i], key1, key2, key3);
        fprintf(csv_file, "%s,%.6f\n", size_labels[i], avg_entropy);
    }

    // Close the CSV file
    fclose(csv_file);

    printf("Entropy results have been written to des3_cbc_entropy_results.csv\n");

    return 0;
}
