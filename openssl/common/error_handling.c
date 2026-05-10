#include "error_handling.h"
#include <openssl/err.h>
#include <stdio.h>

void handleErrors(void) {
    fprintf(stderr, "Wystapil blad. Zrzut stosu bledow OpenSSL:\n");
    ERR_print_errors_fp(stderr);
}

//void print_hex(const char* title, const unsigned char* data, size_t len) {
//    printf("%s (%zu bajtow): ", title, len);
//    for (size_t i = 0; i < len; i++) {
//        printf("%02x", data[i]);
//    }
//    printf("\n");
//}