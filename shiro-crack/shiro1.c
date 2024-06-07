#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define OUT

void sha512_iterate_hash(const uint8_t *salt, size_t salt_len, const char *password,
                         const size_t password_len, const uint32_t iterations,
                         OUT uint8_t *md)
{
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, salt, salt_len);
    SHA512_Update(&ctx, password, password_len);

    SHA512_Final(md, &ctx);

    // Print the salt
    printf("Salt (hex): ");
    for (int i = 0; i < salt_len; i++) {
	printf("%02x", salt[i]);
    }
    printf("\n");

    // Print the initial hash (digest of salt and password) in hexadecimal format
    printf("Initial hash (hex): ");
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        printf("%02x", md[i]);
    }
    printf("\n");

    uint32_t i;
    for (i = 0; i < iterations - 1; i++) {
        SHA512_Init(&ctx);
        SHA512_Update(&ctx, md, SHA512_DIGEST_LENGTH);
        SHA512_Final(md, &ctx);
    }

    // Print the final hash in hexadecimal format
    printf("Final hash (hex): ");
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        printf("%02x", md[i]);
    }
    printf("\n");
}

int base64_decode(const char *base64, uint8_t **out, size_t *out_len) {
    BIO *bio, *b64;
    int decode_len = strlen(base64);
    *out = malloc(decode_len);
    if (*out == NULL) {
        return -1;
    }

    bio = BIO_new_mem_buf(base64, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    *out_len = BIO_read(bio, *out, decode_len);
    BIO_free_all(bio);

    if (*out_len == 0) {
        free(*out);
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <password_file> <shiro_hash>\n", argv[0]);
        return 1;
    }

    // Parse the shiro_hash
    char *shiro_hash = argv[2];
    char *token;
    const char delim[2] = "$";
    int iterations;
    char *salt_b64;
    char *check_b64;

    // Tokenize the shiro_hash
    token = strtok(shiro_hash, delim);
    if (token == NULL || strcmp(token, "shiro1") != 0) {
        fprintf(stderr, "Invalid hash format\n");
        return 1;
    }

    token = strtok(NULL, delim);
    if (token == NULL || strcmp(token, "SHA-512") != 0) {
        fprintf(stderr, "Invalid hash format\n");
        return 1;
    }

    token = strtok(NULL, delim);
    if (token == NULL) {
        fprintf(stderr, "Invalid hash format\n");
        return 1;
    }
    iterations = atoi(token);

    token = strtok(NULL, delim);
    if (token == NULL) {
        fprintf(stderr, "Invalid hash format\n");
        return 1;
    }
    salt_b64 = strdup(token);

    token = strtok(NULL, delim);
    if (token == NULL) {
        fprintf(stderr, "Invalid hash format\n");
        return 1;
    }
    check_b64 = strdup(token);

    // Decode salt
    uint8_t *salt;
    size_t salt_len;
    if (base64_decode(salt_b64, &salt, &salt_len) != 0) {
        fprintf(stderr, "Failed to decode base64 salt\n");
        return 1;
    }

    // Decode check hash
    uint8_t *check;
    size_t check_len;
    if (base64_decode(check_b64, &check, &check_len) != 0) {
        fprintf(stderr, "Failed to decode base64 check hash\n");
        free(salt);
        return 1;
    }

    if (check_len != SHA512_DIGEST_LENGTH) {
        fprintf(stderr, "Invalid check hash length\n");
        free(salt);
        free(check);
        return 1;
    }

    FILE *password_file = fopen(argv[1], "r");
    if (password_file == NULL) {
        printf("Failed opening file\n");
        free(salt);
        free(check);
        return 1;
    }

    // Read all lines
    char **passwords = malloc(1000 * sizeof(char *));
    char *line = NULL;
    size_t line_len = 0;
    ssize_t size_read;
    uint32_t i = 0;
    while ((size_read = getline(&line, &line_len, password_file)) != -1) {
        line[strlen(line) - 1] = 0; // remove newline
        passwords[i++] = strdup(line);
        if (i && (i % 1000) == 0) {
            passwords = realloc(passwords, (i + 1000) * sizeof(char *));
        }
    }
    fclose(password_file);
    uint32_t nb_lines = i;

    printf("[+] Done buffering passwords\n");

    // Check hashes
    #pragma omp parallel
    #pragma omp for
    for (i = 0; i < nb_lines; i++) {
        uint8_t md[SHA512_DIGEST_LENGTH];
        sha512_iterate_hash(salt, salt_len, passwords[i], strlen(passwords[i]), iterations, (uint8_t *)&md);
        if (memcmp(md, check, SHA512_DIGEST_LENGTH) == 0) {
            printf("Found match for %s\n", passwords[i]);
            exit(0);
        }
        free(passwords[i]);
    }
    free(passwords);
    free(salt);
    free(check);
    free(salt_b64);
    free(check_b64);

    return 0;
}

