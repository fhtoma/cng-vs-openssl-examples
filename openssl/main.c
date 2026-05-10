#include <stdio.h>

#include "AES/aes.h"
#include "DSA/dsa.h"

int main(void) {
    if (demonstrate_aes()) {
        fprintf(stderr, "\n!!! Aplikacja przerwala dzialanie z powodu bledu w module AES.\n");
        return 1;
    }

    if (demonstrate_dsa()) {
        fprintf(stderr, "\n!!! Aplikacja przerwala dzialanie z powodu bledu w module DSA.\n");
        return 1;
    }

    printf(">>> Wszystkie demonstracje OpenSSL zakonczone pelnym sukcesem. <<<\n");
    return 0;
}