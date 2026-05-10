#include "dsa.h"
#include "../Common/error_handling.h"

#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <ntstatus.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

int demonstrate_dsa(void) {
    wprintf(L"--- Demonstracja DSA (CNG) ---\n");
    int final_status = -1;

    BCRYPT_ALG_HANDLE hDsaAlg = NULL, hHashAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = 0;

    PBYTE pbHashObject = NULL, pbHash = NULL, pbSignature = NULL;
    DWORD cbHashObject = 0, cbHash = 0, cbSignature = 0, cbData = 0, dwKeyLen = 2048;

    const BYTE rgbMsg[] = "Przykladowy tekst jawny do podpisania!";

    do {
        // --- Obliczanie skrotu wiadomosci ---
        if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hHashAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) { handleErrors(status, L"BCryptOpenAlgorithmProvider (Hash)"); break; }

        if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hDsaAlg, BCRYPT_DSA_ALGORITHM, NULL, 0))) { handleErrors(status, L"BCryptOpenAlgorithmProvider (DSA)"); break; }

        if (!NT_SUCCESS(status = BCryptGetProperty(hHashAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0))) { handleErrors(status, L"BCryptGetProperty (HashObject)"); break; }
        pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
        if (!pbHashObject) { handleErrors(STATUS_NO_MEMORY, L"HeapAlloc (HashObject)"); break; }

        if (!NT_SUCCESS(status = BCryptGetProperty(hHashAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0))) { handleErrors(status, L"BCryptGetProperty (HashLength)"); break; }
        pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
        if (!pbHash) { handleErrors(STATUS_NO_MEMORY, L"HeapAlloc (Hash)"); break; }

        if (!NT_SUCCESS(status = BCryptCreateHash(hHashAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0))) { handleErrors(status, L"BCryptCreateHash"); break; }

        if (!NT_SUCCESS(status = BCryptHashData(hHash, (PBYTE)rgbMsg, sizeof(rgbMsg), 0))) { handleErrors(status, L"BCryptHashData"); break; }

        if (!NT_SUCCESS(status = BCryptFinishHash(hHash, pbHash, cbHash, 0))) { handleErrors(status, L"BCryptFinishHash"); break; }

        // --- Generowanie klucza DSA ---
        if (!NT_SUCCESS(status = BCryptGenerateKeyPair(hDsaAlg, &hKey, dwKeyLen, 0))) { handleErrors(status, L"BCryptGenerateKeyPair"); break; }

        if (!NT_SUCCESS(status = BCryptFinalizeKeyPair(hKey, 0))) { handleErrors(status, L"BCryptFinalizeKeyPair"); break; }

        // --- Podpisywanie wiadomosci ---
        if (!NT_SUCCESS(status = BCryptSignHash(hKey, NULL, pbHash, cbHash, NULL, 0, &cbSignature, 0))) { handleErrors(status, L"BCryptSignHash (size)"); break; }
        pbSignature = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbSignature);
        if (!pbSignature) { handleErrors(STATUS_NO_MEMORY, L"HeapAlloc (Signature)"); break; }

        if (!NT_SUCCESS(status = BCryptSignHash(hKey, NULL, pbHash, cbHash, pbSignature, cbSignature, &cbSignature, 0))) { handleErrors(status, L"BCryptSignHash"); break; }

        // --- Weryfikacja podpisu ---
        status = BCryptVerifySignature(hKey, NULL, pbHash, cbHash, pbSignature, cbSignature, 0);
        if (status == STATUS_SUCCESS) {
            wprintf(L"Wynik: Podpis jest POPRAWNY.\n");
        }
        else if (status == STATUS_INVALID_SIGNATURE) {
            wprintf(L"Wynik: Podpis jest NIEPOPRAWNY.\n");
        }
        else {
            wprintf(L"Blad podczas weryfikacji.\n");
            handleErrors(status, L"BCryptVerifySignature");
            break;
        }
        final_status = 0;

    } while (0);

    // --- Sprzatanie ---
    if (hDsaAlg) BCryptCloseAlgorithmProvider(hDsaAlg, 0);
    if (hHashAlg) BCryptCloseAlgorithmProvider(hHashAlg, 0);
    if (hKey) BCryptDestroyKey(hKey);
    if (hHash) BCryptDestroyHash(hHash);
    if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
    if (pbHash) HeapFree(GetProcessHeap(), 0, pbHash);
    if (pbSignature) HeapFree(GetProcessHeap(), 0, pbSignature);
    wprintf(L"-----------------------------\n\n");
    
    return final_status;
}
