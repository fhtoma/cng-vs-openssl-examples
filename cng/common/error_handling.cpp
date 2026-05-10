#include "error_handling.h"
#include <stdio.h>

void handleErrors(NTSTATUS status, LPCWSTR failed_function) {
    fwprintf(stderr, L"Wystapil blad w funkcji %s. Kod statusu: 0x%08X\n", failed_function, status);
}

//void PrintBytes(IN BYTE* pbPrintData, IN DWORD cbDataLen) {
//    DWORD dwCount = 0;
//
//    for (dwCount = 0; dwCount < cbDataLen; dwCount++)
//    {
//        printf("%02x", pbPrintData[dwCount]);
//    }
//    printf("\n");
//}