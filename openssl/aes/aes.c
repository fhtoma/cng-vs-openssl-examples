#include "aes.h"
#include "../Common/error_handling.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <string.h>
#include <stdio.h>


#define AES_256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define AES_GCM_IV_SIZE 12
#define GCM_TAG_SIZE 16

static int demo_aes_ecb();
static int demo_aes_cbc();
static int demo_aes_gcm();

int demonstrate_aes(void) {
    printf("--- Demonstracja AES (OpenSSL) ---\n");
    if (demo_aes_ecb()) return -1;
    if (demo_aes_cbc()) return -1;
    if (demo_aes_gcm()) return -1;
    printf("------------------------\n\n");
    return 0;
}

static int demo_aes_ecb() {
    printf("Tryb: AES-256-ECB\n");
    int ret = -1;
    const unsigned char* plaintext = (unsigned char*)"Przykladowy tekst jawny do zaszyfrowania!";
    int plaintext_len = (int)strlen((char*)plaintext);
    unsigned char ciphertext[128], decryptedtext[128];
    int decryptedtext_len = 0, ciphertext_len = 0, len = 0;
    unsigned char key[AES_256_KEY_SIZE];

    EVP_CIPHER_CTX* ctx = NULL;
    EVP_CIPHER* cipher_type = NULL;

    do {
        if (!RAND_bytes_ex(NULL, key, sizeof(key), AES_256_KEY_SIZE * 8)) { handleErrors(); break; }

        cipher_type = EVP_CIPHER_fetch(NULL, "AES-256-ECB", NULL);
        if (!cipher_type) { handleErrors(); break; }

        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { handleErrors(); break; }

        // --- Szyfrowanie ---
        if (!EVP_EncryptInit_ex2(ctx, cipher_type, key, NULL, NULL)) { handleErrors(); break; }
        if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) { handleErrors(); break; }
        ciphertext_len = len;
        if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) { handleErrors(); break; }
        ciphertext_len += len;

        if (!EVP_CIPHER_CTX_reset(ctx)) { handleErrors(); break; }
        
        // --- Deszyfrowanie ---
        if (!EVP_DecryptInit_ex2(ctx, cipher_type, key, NULL, NULL)) { handleErrors(); break; }
        if (!EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertext_len)) { handleErrors(); break; }
        decryptedtext_len = len;
        if (!EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len)) { handleErrors(); break; }
        decryptedtext_len += len;
        decryptedtext[decryptedtext_len] = '\0';

        printf("Wynik: Odszyfrowany tekst: \"%s\"\n", decryptedtext);
        ret = 0;

    } while (0);

    // --- Sprzatanie ---
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher_type);
    return ret;
}

static int demo_aes_cbc() {
    printf("Tryb: AES-256-CBC\n");
    int ret = -1;
    const unsigned char* plaintext = (unsigned char*)"Przykladowy tekst jawny do zaszyfrowania!";
    int plaintext_len = (int)strlen((char*)plaintext);
    unsigned char ciphertext[128], decryptedtext[128];
    int decryptedtext_len = 0, ciphertext_len = 0, len = 0;
    unsigned char key[AES_256_KEY_SIZE], iv[AES_BLOCK_SIZE];

    EVP_CIPHER_CTX* ctx = NULL;
    EVP_CIPHER* cipher_type = NULL;

    do {
        if (!RAND_bytes_ex(NULL, key, sizeof(key), 0)) { handleErrors(); break; }
        if (!RAND_bytes_ex(NULL, iv, sizeof(iv), 0)) { handleErrors(); break; }

        cipher_type = EVP_CIPHER_fetch(NULL, "AES-256-CBC", NULL);
        if (!cipher_type) { handleErrors(); break; }

        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { handleErrors(); break; }

        // --- Szyfrowanie ---
        if (!EVP_EncryptInit_ex2(ctx, cipher_type, key, iv, NULL)) { handleErrors(); break; }
        if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) { handleErrors(); break; }
        ciphertext_len = len;
        if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) { handleErrors(); break; }
        ciphertext_len += len;

        if (!EVP_CIPHER_CTX_reset(ctx)) { handleErrors(); break; }

        // --- Deszyfrowanie ---
        if (!EVP_DecryptInit_ex2(ctx, cipher_type, key, iv, NULL)) { handleErrors(); break; }
        if (!EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertext_len)) { handleErrors(); break; }
        decryptedtext_len = len;
        if (!EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len)) { handleErrors(); break; }
        decryptedtext_len += len;
        decryptedtext[decryptedtext_len] = '\0';

        printf("Wynik: Odszyfrowany tekst: \"%s\"\n", decryptedtext);
        ret = 0;

    } while (0);

    // --- Sprzatanie ---
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher_type);
    return ret;
}

static int demo_aes_gcm() {
    printf("Tryb: AES-256-GCM\n");
    int ret = -1;
    const unsigned char* plaintext = (unsigned char*)"Przykladowy tekst jawny do zaszyfrowania!";
    int plaintext_len = (int)strlen((char*)plaintext);
    const unsigned char aad[] = "Dodatkowe dane do uwierzytelnienia";
    int aad_len = (int)strlen((char*)aad);
    unsigned char ciphertext[128], decryptedtext[128], tag[GCM_TAG_SIZE];
    int len = 0, ciphertext_len = 0, decryptedtext_len = 0;
    unsigned char key[AES_256_KEY_SIZE], iv[AES_GCM_IV_SIZE];

    EVP_CIPHER_CTX* ctx = NULL;
    EVP_CIPHER* cipher_type = NULL;

    do {
        if (!RAND_bytes_ex(NULL, key, sizeof(key), 0)) { handleErrors(); break; }
        if (!RAND_bytes_ex(NULL, iv, sizeof(iv), 0)) { handleErrors(); break; }

        cipher_type = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
        if (!cipher_type) { handleErrors(); break; }

        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { handleErrors(); break; }

        // --- Szyfrowanie ---
        if (!EVP_EncryptInit_ex2(ctx, cipher_type, key, iv, NULL)) { handleErrors(); break; }
        if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) { handleErrors(); break; }
        if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) { handleErrors(); break; }
        ciphertext_len = len;
        if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) { handleErrors(); break; }
        ciphertext_len += len;
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, GCM_TAG_SIZE),
            OSSL_PARAM_construct_end()
        };
        if (!EVP_CIPHER_CTX_get_params(ctx, params)) { handleErrors(); break; }

        if (!EVP_CIPHER_CTX_reset(ctx)) { handleErrors(); break; }

        // --- Deszyfrowanie ---
        if (!EVP_DecryptInit_ex2(ctx, cipher_type, key, iv, params)) { handleErrors(); break; }
        if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) { handleErrors(); break; }
        if (!EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertext_len)) { handleErrors(); break; }
        decryptedtext_len = len;

        if (EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len)) {
            decryptedtext_len += len;
            decryptedtext[decryptedtext_len] = '\0';
            printf("Wynik: Uwierzytelnienie i deszyfracja udane (tag poprawny).\n");
            printf("Odszyfrowany tekst: \"%s\"\n", decryptedtext);
        }
        else {
            printf("Wynik: Uwierzytelnienie nie powiodlo sie! (tag niepoprawny).\n");
        }
        ret = 0;

    } while (0);

    // --- Sprzatanie ---
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher_type);
    return ret;
}