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

#define ITERATIONS 5
#define UNROLL_FACTOR 4  // Unrolling factor for optimization

void test_encryption_time(size_t data_size, uint64_t key1, uint64_t key2, uint64_t key3) {
    double total_enc_time = 0, total_dec_time = 0;

    // Memory allocation with OS-specific handling
    uint8_t *data;
#ifdef _WIN32
    data = (uint8_t *)malloc(data_size);
    if (!data) {
        fprintf(stderr, "Memory allocation failed for %zu Bytes!\n", data_size);
        exit(1);
    }
#else
    if (posix_memalign((void **)&data, 16, data_size) != 0) {
        fprintf(stderr, "Memory allocation failed for %zu Bytes!\n", data_size);
        exit(1);
    }
#endif
    printf("Memory allocated successfully for %zu Bytes!\n", data_size);
    fflush(stdout);

    uint8_t iv[8], decrypt_iv[8];
    for (int i = 0; i < 8; i++) iv[i] = rand() & 0xFF;

    for (int i = 0; i < ITERATIONS; i++) {
        // Fill random data efficiently
        for (size_t j = 0; j < data_size; j += 8) {
            ((uint64_t *)data)[j / 8] = rand();
        }
        memcpy(decrypt_iv, iv, 8);

        // **Optimized 3DES CBC Encryption**
        printf("Encrypting %zu bytes (iteration %d)...\n", data_size, i + 1);
        fflush(stdout);
        double start_enc = get_time();
        for (size_t j = 0; j < data_size; j += 8 * UNROLL_FACTOR) {
            for (int k = 0; k < UNROLL_FACTOR && j + k * 8 < data_size; k++) {
                des3_cbc_encrypt(data + j + k * 8, 8, key1, key2, key3, iv);
            }
        }
        double end_enc = get_time();
        total_enc_time += (end_enc - start_enc);
        printf("Encryption Done!\n");
        fflush(stdout);

        // **Optimized 3DES CBC Decryption**
        printf("Decrypting %zu bytes (iteration %d)...\n", data_size, i + 1);
        fflush(stdout);
        double start_dec = get_time();
        for (size_t j = 0; j < data_size; j += 8 * UNROLL_FACTOR) {
            for (int k = 0; k < UNROLL_FACTOR && j + k * 8 < data_size; k++) {
                des3_cbc_decrypt(data + j + k * 8, 8, key1, key2, key3, decrypt_iv);
            }
        }
        double end_dec = get_time();
        total_dec_time += (end_dec - start_dec);
        printf("Decryption Done!\n");
        fflush(stdout);
    }

    free(data);  // Free allocated memory

    printf("Data Size: %zu Bytes\n", data_size);
    printf("Average 3DES Encryption Time: %.9f seconds\n", total_enc_time / ITERATIONS);
    printf("Average 3DES Decryption Time: %.9f seconds\n", total_dec_time / ITERATIONS);
    printf("-----------------------------------------\n");
    fflush(stdout);
}

int main() {
    printf("Starting optimized 3DES encryption test...\n");
    fflush(stdout);

    srand(time(NULL));

    // Initialize 3DES keys
    uint64_t key1 = 0x133457799BBCDFF1;
    uint64_t key2 = 0x1122334455667788;
    uint64_t key3 = 0xAABB09182736CCDD;

    test_encryption_time(8, key1, key2, key3);
    test_encryption_time(16, key1, key2, key3);
    test_encryption_time(1024, key1, key2, key3);
    test_encryption_time(1048576, key1, key2, key3);

    printf("3DES encryption test completed!\n");
    fflush(stdout);
    return 0;
}