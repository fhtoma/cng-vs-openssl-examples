#include "dsa.h"
#include "../Common/error_handling.h"

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <string.h>
#include <stdio.h>

int demonstrate_dsa(void) {
    printf("--- Demonstracja DSA (OpenSSL) ---\n");
    int ret = -1;

    EVP_PKEY* param_key = NULL;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* pctx = NULL;
    EVP_MD_CTX* mctx = NULL;
    unsigned char* signature = NULL;

    do {
        // --- Generowanie parametrow DSA ---
        pctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL);
        if (!pctx) { handleErrors(); break; }
        if(!EVP_PKEY_paramgen_init(pctx)) { handleErrors(); break; }

        unsigned int pbits = 2048;
        unsigned int qbits = 256;
        int gindex = 2;
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_FFC_PBITS, &pbits),
            OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_FFC_QBITS, &qbits),
            OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_FFC_GINDEX, &gindex),
            OSSL_PARAM_construct_end()
        };

        if (!EVP_PKEY_CTX_set_params(pctx, params)) { handleErrors(); break; }
        if (!EVP_PKEY_generate(pctx, &param_key)) { handleErrors(); break; };
        EVP_PKEY_CTX_free(pctx);
        pctx = NULL;

        //// --- Generowanie klucza DSA ---
        pctx = EVP_PKEY_CTX_new_from_pkey(NULL, param_key, NULL);
        if (!pctx) { handleErrors(); break; }
        if (!EVP_PKEY_keygen_init(pctx)) { handleErrors(); break; };
        if (!EVP_PKEY_generate(pctx, &pkey)) { handleErrors(); break; }

        const unsigned char* message = (unsigned char*)"Przykladowy tekst jawny do podpisania.";
        size_t message_len = strlen((char*)message);
        size_t signature_len = 0;

        // --- Podpisywanie wiadomosci ---
        mctx = EVP_MD_CTX_new();
        if (!mctx) { handleErrors(); break; }
        if (!EVP_DigestSignInit_ex(mctx, NULL, OSSL_DIGEST_NAME_SHA2_256, NULL, NULL, pkey, NULL)) { handleErrors(); break; }
        if (!EVP_DigestSignUpdate(mctx, message, message_len)) { handleErrors(); break; }
        if (!EVP_DigestSignFinal(mctx, NULL, &signature_len)) { handleErrors(); break; }

        signature = malloc(signature_len);
        if (!signature) { fprintf(stderr, "Blad alokacji pamieci\n"); break; }
        if (!EVP_DigestSignFinal(mctx, signature, &signature_len)) { handleErrors(); break; }

        // --- Weryfikacja podpisu ---
        EVP_MD_CTX_reset(mctx);

        if (!EVP_DigestVerifyInit_ex(mctx, NULL, OSSL_DIGEST_NAME_SHA2_256, NULL, NULL, pkey, NULL)) { handleErrors(); break; }
        if (!EVP_DigestVerifyUpdate(mctx, message, message_len)) { handleErrors(); break; }

        int verification_status = EVP_DigestVerifyFinal(mctx, signature, signature_len);
        if (verification_status == 1) {
            printf("Wynik: Podpis jest POPRAWNY.\n");
        }
        else if (verification_status == 0) {
            printf("Wynik: Podpis jest NIEPOPRAWNY.\n");
        }
        else {
            printf("Blad podczas weryfikacji.\n");
            handleErrors();
            break;
        }
        ret = 0;

    } while (0);

    // --- Sprzatanie ---
    EVP_PKEY_free(param_key);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    EVP_MD_CTX_free(mctx);
    free(signature);
    printf("------------------------\n\n");
    return ret;
}