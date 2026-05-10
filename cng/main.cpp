#include <stdio.h>
#include <windows.h>

#include "AES/aes.h"
#include "DSA/dsa.h"

int main(void) {
    if (demonstrate_aes()) {
        fwprintf(stderr, L"\n!!! Aplikacja przerwala dzialanie z powodu bledu w module AES.\n");
        return 1;
    }

    if (demonstrate_dsa()) {
        fwprintf(stderr, L"\n!!! Aplikacja przerwala dzialanie z powodu bledu w module DSA.\n");
        return 1;
    }

    wprintf(L"\n>>> Wszystkie demonstracje CNG zakonczone pelnym sukcesem. <<<\n");
    return 0;
}
