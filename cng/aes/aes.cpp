#include "aes.h"
#include "../Common/error_handling.h"

#include <ntstatus.h>
#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>


#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define AES_256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define AES_GCM_NONCE_SIZE 12
#define GCM_TAG_SIZE 16

static int demo_aes_ecb(void);
static int demo_aes_cbc(void);
static int demo_aes_gcm(void);

int demonstrate_aes(void) {
    wprintf(L"--- Demonstracja AES (CNG) ---\n");
    if (demo_aes_ecb()) return -1;
    if (demo_aes_cbc()) return -1;
    if (demo_aes_gcm()) return -1;
    wprintf(L"-----------------------------\n\n");
    return 0;
}

static int demo_aes_ecb() {
    wprintf(L"Tryb: AES-256-ECB\n");
    int final_status = -1;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = 0;

    PBYTE pbCipherText = NULL, pbPlainText = NULL, pbKeyObject = NULL;
    DWORD cbCipherText = 0, cbPlainText = 0, cbData = 0, cbKeyObject = 0;

    const BYTE rgbPlainText[] = "Przykladowy tekst jawny do zaszyfrowania!";
    BYTE rgbKey[AES_256_KEY_SIZE];

    do {
        if (!NT_SUCCESS(status = BCryptGenRandom(NULL, rgbKey, sizeof(rgbKey), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) { handleErrors(status, L"BCryptGenRandom (key)"); break; }

        if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) { handleErrors(status, L"BCryptOpenAlgorithmProvider"); break; }

        if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0))) { handleErrors(status, L"BCryptGetProperty (ECB)"); break; }
        pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
        if(!pbKeyObject) { handleErrors(STATUS_NO_MEMORY, L"HeapAlloc (pbKeyObject)"); break; }

        if (!NT_SUCCESS(status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0))) { handleErrors(status, L"BCryptSetProperty (ECB)"); break;}

        if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE) rgbKey, sizeof(rgbKey), 0))) { handleErrors(status, L"BCryptGenerateSymmetricKey"); break; }

        cbPlainText = sizeof(rgbPlainText);
        pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
        if (!pbPlainText) { handleErrors(STATUS_NO_MEMORY, L"HeapAlloc (pbPlainText)"); break; }
        memcpy(pbPlainText, rgbPlainText, sizeof(rgbPlainText));

        // --- Szyfrowanie ---
        if (!NT_SUCCESS(status = BCryptEncrypt(hKey, pbPlainText, cbPlainText, NULL, NULL, 0, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING))) { handleErrors(status, L"BCryptEncrypt (size calc)"); break; }

        pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
        if (!pbCipherText) { handleErrors(STATUS_NO_MEMORY, L"HeapAlloc (CipherText)"); break; }

        if (!NT_SUCCESS(status = BCryptEncrypt(hKey, (PBYTE)pbPlainText, cbPlainText, NULL, NULL, 0, pbCipherText, cbCipherText, &cbData, BCRYPT_BLOCK_PADDING))) { handleErrors(status, L"BCryptEncrypt"); break; }

        if (pbPlainText) { HeapFree(GetProcessHeap(), 0, pbPlainText); }
        pbPlainText = NULL;

        // --- Deszyfrowanie ---
        if (!NT_SUCCESS(status = BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL, NULL, 0, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING))) { handleErrors(status, L"BCryptDecrypt (size calc)"); break; }

        pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
        if (!pbPlainText) { handleErrors(STATUS_NO_MEMORY, L"HeapAlloc (PlainText)"); break; }

        if (!NT_SUCCESS(status = BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL, NULL, 0, pbPlainText, cbPlainText, &cbPlainText, BCRYPT_BLOCK_PADDING))) { handleErrors(status, L"BCryptDecrypt"); break; }

        if (0 != memcmp(pbPlainText, (PBYTE)rgbPlainText, sizeof(rgbPlainText))) {
            wprintf(L"BLAD: Odszyfrowany tekst nie zgadza sie z oryginalem!\n");
        } else {
            wprintf(L"Wynik: Odszyfrowany tekst jest poprawny.\n");
        }
        final_status = 0;

    } while (0);

    // --- Sprzatanie ---
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (pbCipherText) HeapFree(GetProcessHeap(), 0, pbCipherText);
    if (pbPlainText) HeapFree(GetProcessHeap(), 0, pbPlainText);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    
    return final_status;
}


static int demo_aes_cbc() {
    wprintf(L"Tryb: AES-256-CBC\n");
    int final_status = -1;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = 0;

    PBYTE pbCipherText = NULL, pbPlainText = NULL, pbIV = NULL, pbKeyObject = NULL;
    DWORD cbCipherText = 0, cbPlainText = 0, cbData = 0, cbKeyObject = 0;

    const BYTE rgbPlainText[] = "Przykladowy tekst jawny do zaszyfrowania!";
    BYTE rgbKey[AES_256_KEY_SIZE], rgbIV[AES_BLOCK_SIZE];

    do {
        if (!NT_SUCCESS(status = BCryptGenRandom(NULL, rgbKey, sizeof(rgbKey), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) { handleErrors(status, L"BCryptGenRandom (key)"); break; }
        
        if (!NT_SUCCESS(status = BCryptGenRandom(NULL, rgbIV, sizeof(rgbIV), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) { handleErrors(status, L"BCryptGenRandom (key)"); break; }

        if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) { handleErrors(status, L"BCryptOpenAlgorithmProvider"); break; }

        pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, AES_BLOCK_SIZE);
        if (!pbIV) { handleErrors(STATUS_NO_MEMORY, L"HeapAlloc (IV)"); break; }
        memcpy(pbIV, rgbIV, AES_BLOCK_SIZE);

        if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0))) { handleErrors(status, L"BCryptGetProperty (ECB)"); break; }
        pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
        if (!pbKeyObject) { handleErrors(STATUS_NO_MEMORY, L"HeapAlloc (pbKeyObject)"); break; }

        if (!NT_SUCCESS(status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) { handleErrors(status, L"BCryptSetProperty (CBC)"); break; }
        
        if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE) rgbKey, sizeof(rgbKey), 0))) { handleErrors(status, L"BCryptGenerateSymmetricKey"); break; }

        cbPlainText = sizeof(rgbPlainText);
        pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
        if (!pbPlainText) { handleErrors(STATUS_NO_MEMORY, L"HeapAlloc (pbPlainText)"); break; }
        memcpy(pbPlainText, rgbPlainText, sizeof(rgbPlainText));

        // --- Szyfrowanie ---
        if (!NT_SUCCESS(status = BCryptEncrypt(hKey, (PBYTE)pbPlainText, cbPlainText, NULL, pbIV, AES_BLOCK_SIZE, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING))) { handleErrors(status, L"BCryptEncrypt (size calc)"); break; }
        
        pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
        if (!pbCipherText) { handleErrors(STATUS_NO_MEMORY, L"HeapAlloc (CipherText)"); break; }

        if (!NT_SUCCESS(status = BCryptEncrypt(hKey, (PBYTE)pbPlainText, cbPlainText, NULL, pbIV, AES_BLOCK_SIZE, pbCipherText, cbCipherText, &cbData, BCRYPT_BLOCK_PADDING))) { handleErrors(status, L"BCryptEncrypt"); break; }

        if (pbPlainText) { HeapFree(GetProcessHeap(), 0, pbPlainText); }
        pbPlainText = NULL;

        memcpy(pbIV, rgbIV, AES_BLOCK_SIZE);

        // --- Deszyfrowanie ---
        if (!NT_SUCCESS(status = BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL, pbIV, AES_BLOCK_SIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING))) { handleErrors(status, L"BCryptDecrypt (size calc)"); break; }
        
        pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
        if (!pbPlainText) { handleErrors(STATUS_NO_MEMORY, L"HeapAlloc (PlainText)"); break; }
        
        if (!NT_SUCCESS(status = BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL, pbIV, AES_BLOCK_SIZE, pbPlainText, cbPlainText, &cbPlainText, BCRYPT_BLOCK_PADDING))) { handleErrors(status, L"BCryptDecrypt"); break; }

        if (0 != memcmp(pbPlainText, (PBYTE)rgbPlainText, sizeof(rgbPlainText))) {
            wprintf(L"BLAD: Odszyfrowany tekst nie zgadza sie z oryginalem!\n");
        } else {
            wprintf(L"Wynik: Odszyfrowany tekst jest poprawny.\n");
        }
        final_status = 0;

    } while (0);

    // --- Sprzatanie ---
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (pbCipherText) HeapFree(GetProcessHeap(), 0, pbCipherText);
    if (pbPlainText) HeapFree(GetProcessHeap(), 0, pbPlainText);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbIV) HeapFree(GetProcessHeap(), 0, pbIV);

    return final_status;
}


static int demo_aes_gcm() {
    wprintf(L"Tryb: AES-256-GCM\n");
    int final_status = -1;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = 0;

    PBYTE pbCipherText = NULL, pbPlainText = NULL, pbKeyObject = NULL;
    PBYTE pbNonce = NULL, pbTag = NULL, pbAAD = NULL;
    DWORD cbCipherText = 0, cbPlainText = 0, cbKeyObject = 0, cbData = 0;

    const BYTE rgbPlainText[] = "Przykladowy tekst jawny do zaszyfrowania!";
    const BYTE rgbAAD[] = "Dodatkowe dane do uwierzytelnienia";
    BYTE rgbKey[AES_256_KEY_SIZE], rgbNonce[AES_GCM_NONCE_SIZE];

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

    do {
        if (!NT_SUCCESS(status = BCryptGenRandom(NULL, rgbKey, sizeof(rgbKey), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) { handleErrors(status, L"BCryptGenRandom (key)"); break; }

        if (!NT_SUCCESS(status = BCryptGenRandom(NULL, rgbNonce, AES_GCM_NONCE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) { handleErrors(status, L"BCryptGenRandom (Nonce)"); break; }

        if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) { handleErrors(status, L"BCryptOpenAlgorithmProvider"); break; }

        pbNonce = (PBYTE)HeapAlloc(GetProcessHeap(), 0, AES_GCM_NONCE_SIZE);
        if (!pbNonce) { handleErrors(STATUS_NO_MEMORY, L"HeapAlloc (IV)"); break; }
        memcpy(pbNonce, rgbNonce, AES_GCM_NONCE_SIZE);

        if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0))) { handleErrors(status, L"BCryptGetProperty (KeyObject)"); break; }
        pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
        if (!pbKeyObject) { handleErrors(STATUS_NO_MEMORY, L"HeapAlloc (KeyObject)"); break; }

        if (!NT_SUCCESS(status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) { handleErrors(status, L"BCryptSetProperty (GCM)"); break; }

        if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, rgbKey, sizeof(rgbKey), 0))) { handleErrors(status, L"BCryptGenerateSymmetricKey"); break; }

        pbTag = (PBYTE)HeapAlloc(GetProcessHeap(), 0, GCM_TAG_SIZE);
        if (!pbTag) { handleErrors(STATUS_NO_MEMORY, L"HeapAlloc (Tag)"); break; }

        cbPlainText = sizeof(rgbPlainText);
        pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
        if (!pbPlainText) { handleErrors(STATUS_NO_MEMORY, L"HeapAlloc (pbPlainText)"); break; }
        memcpy(pbPlainText, rgbPlainText, sizeof(rgbPlainText));

        // --- Szyfrowanie ---
        authInfo.pbNonce = pbNonce;
        authInfo.cbNonce = AES_GCM_NONCE_SIZE;
        authInfo.pbAuthData = (PBYTE)rgbAAD;
        authInfo.cbAuthData = sizeof(rgbAAD);
        authInfo.pbTag = pbTag;
        authInfo.cbTag = GCM_TAG_SIZE;

        if (!NT_SUCCESS(status = BCryptEncrypt(hKey, (PBYTE)pbPlainText, cbPlainText, &authInfo, NULL, 0, NULL, 0, &cbCipherText, 0))) { handleErrors(status, L"BCryptEncrypt (size)"); break; }
        
        pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
        if (!pbCipherText) { handleErrors(STATUS_NO_MEMORY, L"HeapAlloc (CipherText)"); break; }

        if (!NT_SUCCESS(status = BCryptEncrypt(hKey, (PBYTE)pbPlainText, cbPlainText, &authInfo, NULL, 0, pbCipherText, cbCipherText, &cbData, 0))) { handleErrors(status, L"BCryptEncrypt"); break; }

        // --- Deszyfrowanie ---
        if (!NT_SUCCESS(status = BCryptDecrypt(hKey, pbCipherText, cbCipherText, &authInfo, NULL, 0, NULL, 0, &cbPlainText, 0))) {
            if (status == STATUS_AUTH_TAG_MISMATCH) {
                wprintf(L"Wynik: Uwierzytelnienie NIE powiodlo sie! (tag niepoprawny).\n");
                final_status = 0;
            }
            else {
                handleErrors(status, L"BCryptDecrypt (size)");
            }
            break;
        }

        pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
        if (!pbPlainText) { handleErrors(STATUS_NO_MEMORY, L"HeapAlloc (PlainText)"); break; }

        if (!NT_SUCCESS(status = BCryptDecrypt(hKey, pbCipherText, cbCipherText, &authInfo, NULL, 0, pbPlainText, cbPlainText, &cbPlainText, 0))) {
            if (status == STATUS_AUTH_TAG_MISMATCH) {
                wprintf(L"Wynik: Uwierzytelnienie NIE powiodlo sie! (tag niepoprawny).\n");
                final_status = 0;
            }
            else {
                handleErrors(status, L"BCryptDecrypt");
            }
            break;
        }

        if (0 != memcmp(pbPlainText, (PBYTE)rgbPlainText, sizeof(rgbPlainText))) {
            wprintf(L"BLAD: Odszyfrowany tekst nie zgadza sie z oryginalem!\n");
        } else {
            wprintf(L"Wynik: Odszyfrowany tekst jest poprawny.\n");
        }
        final_status = 0;

    } while (0);

    // --- Sprzatanie ---
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (pbCipherText) HeapFree(GetProcessHeap(), 0, pbCipherText);
    if (pbPlainText) HeapFree(GetProcessHeap(), 0, pbPlainText);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbNonce) HeapFree(GetProcessHeap(), 0, pbNonce);
    if (pbTag) HeapFree(GetProcessHeap(), 0, pbTag);

    return final_status;
}
