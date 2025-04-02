// securefileencrypt - Malware Simulation Edition
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

#define AES_KEY_SIZE 32 // 256-bit AES Key for AES-256
#define RSA_KEY_SIZE 3072 // Strong RSA key for hybrid encryption
#define BUFFER_SIZE 4096 // Buffer size for file I/O

// Function prototypes
RSA *generate_RSA_keys();
void compute_sha256(const char *filename, unsigned char output_hash[SHA256_DIGEST_LENGTH]);
long get_file_size(const char *filename);
void encrypt_file(const char *input_filename, const char *output_filename, AES_KEY *aes_key, int stealth);
void decrypt_file(const char *input_filename, const char *output_filename, AES_KEY *aes_key);

// Generate RSA key pair for encrypting AES key (simulating hybrid encryption like in malware)
RSA *generate_RSA_keys() {
    RSA *rsa = RSA_new();
    BIGNUM *bne = BN_new();
    BN_set_word(bne, RSA_F4); // Common public exponent
    RSA_generate_key_ex(rsa, RSA_KEY_SIZE, bne, NULL);
    BN_free(bne);
    return rsa;
}

// Computes SHA-256 hash of a file to verify its integrity post-encryption
void compute_sha256(const char *filename, unsigned char 
output_hash[SHA256_DIGEST_LENGTH]) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file for hashing");
        return;
    }
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char buffer[BUFFER_SIZE];
    int bytes_read;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        SHA256_Update(&sha256, buffer, bytes_read);
    }
    SHA256_Final(output_hash, &sha256);
    fclose(file);
}

// Gets the file size in bytes (used for comparison before/after encryption)
long get_file_size(const char *filename) {
    struct stat st;
    if (stat(filename, &st) == 0)
        return st.st_size;
    return -1;
}

// Encrypts a file using AES-256
// If 'stealth' mode is enabled, no console output is shown (simulates malware silence)
void encrypt_file(const char *input_filename, const char *output_filename, 
AES_KEY *aes_key, int stealth) {
    FILE *infile = fopen(input_filename, "rb");
    FILE *outfile = fopen(output_filename, "wb");
    unsigned char buffer[BUFFER_SIZE];
    unsigned char encrypted_buffer[BUFFER_SIZE];
    int bytes_read;
    clock_t start, end;

    if (!infile || !outfile) {
        perror("Error opening file");
        return;
    }

    start = clock();
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, infile)) > 0) {
        AES_encrypt(buffer, encrypted_buffer, aes_key);
        fwrite(encrypted_buffer, 1, bytes_read, outfile);
    }
    end = clock();

    fclose(infile);
    fclose(outfile);

    if (!stealth) {
        double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
        printf("Encrypted file: %s\n", output_filename);
        printf("Encryption Time: %.4f seconds\n", time_taken);
    }
}

// Decrypts an encrypted file using AES-256 (used to validate correctness of encryption)
void decrypt_file(const char *input_filename, const char *output_filename, 
AES_KEY *aes_key) {
    FILE *infile = fopen(input_filename, "rb");
    FILE *outfile = fopen(output_filename, "wb");
    unsigned char buffer[BUFFER_SIZE];
    unsigned char decrypted_buffer[BUFFER_SIZE];
    int bytes_read;
    clock_t start, end;

    if (!infile || !outfile) {
        perror("Error opening file");
        return;
    }

    start = clock();
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, infile)) > 0) {
        AES_decrypt(buffer, decrypted_buffer, aes_key);
        fwrite(decrypted_buffer, 1, bytes_read, outfile);
    }
    end = clock();

    fclose(infile);
    fclose(outfile);

    double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Decrypted file: %s\n", output_filename);
    printf("Decryption Time: %.4f seconds\n", time_taken);
}

int main(int argc, char *argv[]) {
    // Check if stealth mode is enabled via CLI argument
    int stealth_mode = 0;
    if (argc > 3 && strcmp(argv[3], "--stealth") == 0) {
        stealth_mode = 1;
    }

    // Validate usage
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <input file> <output file> [--stealth]\n", argv[0]);
        return 1;
    }

    // Generate RSA key pair (simulates secure key transport like in hybrid ransomware)
    RSA *rsa_keys = generate_RSA_keys();

    // Generate random AES key for file encryption
    unsigned char aes_key[AES_KEY_SIZE];
    RAND_bytes(aes_key, AES_KEY_SIZE);

    // Set up AES key structs for encryption and decryption
    AES_KEY enc_aes_key, dec_aes_key;
    AES_set_encrypt_key(aes_key, 256, &enc_aes_key);
    AES_set_decrypt_key(aes_key, 256, &dec_aes_key);

    // Perform file encryption
    encrypt_file(argv[1], argv[2], &enc_aes_key, stealth_mode);

    // Compute and optionally display SHA-256 hash of encrypted file
    unsigned char hash[SHA256_DIGEST_LENGTH];
    compute_sha256(argv[2], hash);
    if (!stealth_mode) {
        printf("SHA-256: ");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", hash[i]);
        printf("\n");

        // Print file size comparison
        long original_size = get_file_size(argv[1]);
        long encrypted_size = get_file_size(argv[2]);
        printf("Original Size: %ld bytes\n", original_size);
        printf("Encrypted Size: %ld bytes\n", encrypted_size);
    }

    // Perform file decryption for verification (can be removed for stealth-only mode)
    decrypt_file(argv[2], "decrypted_output.txt", &dec_aes_key);

    // Clean up RSA key
    RSA_free(rsa_keys);
    return 0;
}

