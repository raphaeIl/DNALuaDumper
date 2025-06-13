#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include "rijndael.h"
#include <iostream>

#define KEYBITS 256

void decrypt_file(const wchar_t* input_path, const wchar_t* output_path, const char* password);
void process_directory(const wchar_t* base_folder, const wchar_t* output_folder, const char* password);
wchar_t* char_to_wchar(const char* str);
void decrypt(const char* input_path, const char* output_path);
char* wchar_to_char(const wchar_t* wstr);

void decrypt(const char* input_path, const char* output_path)
{
    unsigned long rk[RKLENGTH(KEYBITS)];
    unsigned char key[KEYLENGTH(KEYBITS)];
    int i;
    int nrounds;
    const char* password;
    FILE* input;
    password = "q6i7Ix5yL9tJorqdP46NHFmq9wHK+QKYLl/xpTXYFvM=";

    for (i = 0; i < sizeof(key); i++)
        key[i] = *password != 0 ? *password++ : 0;

    input = fopen(input_path, "rb");
    if (input == NULL)
    {
        fprintf(stdout, "input_path: %d", input_path);
        fputs("File read error", stderr);
    }
    nrounds = rijndaelSetupDecrypt(rk, key, 256);

    FILE* output = fopen(output_path, "ab"); // "ab" -> append in binary mode
    if (output == nullptr) {
        perror("Failed to open output file");
    }

    while (1)
    {
        unsigned char plaintext[16];
        unsigned char ciphertext[16];
        int j;
        if (fread(ciphertext, sizeof(ciphertext), 1, input) != 1)
            break;
        rijndaelDecrypt(rk, nrounds, ciphertext, plaintext);

        //fwrite(plaintext, sizeof(plaintext), 1, stdout);
        fwrite(plaintext, sizeof(plaintext), 1, output);
    }

    fclose(output);
    fclose(input);
}

int masin(int argc, char** argv)
{
    unsigned long rk[RKLENGTH(KEYBITS)];
    unsigned char key[KEYLENGTH(KEYBITS)];
    int i;
    int nrounds;
    char* password;
    FILE* output;
    if (argc < 3)
    {
        fputs("Missing argument\n", stderr);
        return 1;
    }
    password = argv[1];
    for (i = 0; i < sizeof(key); i++)
        key[i] = *password != 0 ? *password++ : 0;
    output = fopen(argv[2], "wb");
    if (output == NULL)
    {
        fputs("File write error", stderr);
        return 1;
    }
    nrounds = rijndaelSetupEncrypt(rk, key, 256);
    while (!feof(stdin))
    {
        unsigned char plaintext[16];
        unsigned char ciphertext[16];
        int j;
        for (j = 0; j < sizeof(plaintext); j++)
        {
            int c = getchar();
            if (c == EOF)
                break;
            plaintext[j] = c;
        }
        if (j == 0)
            break;
        for (; j < sizeof(plaintext); j++)
            plaintext[j] = ' ';
        rijndaelEncrypt(rk, nrounds, plaintext, ciphertext);
        if (fwrite(ciphertext, sizeof(ciphertext), 1, output) != 1)
        {
            fclose(output);
            fputs("File write error", stderr);
            return 1;
        }
    }
    fclose(output);
}

// decrypt
int msain(int argc, char** argv)
{
    unsigned long rk[RKLENGTH(KEYBITS)];
    unsigned char key[KEYLENGTH(KEYBITS)];
    int i;
    int nrounds;
    char* password;
    FILE* input;
    if (argc < 3)
    {
        fputs("Missing argument", stderr);
        return 1;
    }
    password = argv[1];
    for (i = 0; i < sizeof(key); i++)
        key[i] = *password != 0 ? *password++ : 0;
    input = fopen(argv[2], "rb");
    if (input == NULL)
    {
        fputs("File read error", stderr);
        return 1;
    }
    nrounds = rijndaelSetupDecrypt(rk, key, 256);
    while (1)
    {
        unsigned char plaintext[16];
        unsigned char ciphertext[16];
        int j;
        if (fread(ciphertext, sizeof(ciphertext), 1, input) != 1)
            break;
        rijndaelDecrypt(rk, nrounds, ciphertext, plaintext);
        fwrite(plaintext, sizeof(plaintext), 1, stdout);
    }
    fclose(input);
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: program.exe <password> <input_folder>\n");
        return 1;
    }

    char* password = argv[1];
    wchar_t* input_folder = char_to_wchar(argv[2]);

    wchar_t output_folder[MAX_PATH] = L"dump";
    CreateDirectory(output_folder, NULL);

    process_directory(input_folder, output_folder, password);

    wprintf(L"Decryption complete. Files saved in '%s' folder.\n", output_folder);

    free(input_folder);
    return 0;
}

void process_directory(const wchar_t* base_folder, const wchar_t* output_folder, const char* password) {
    wchar_t search_path[MAX_PATH];
    WIN32_FIND_DATAW find_data;
    HANDLE hFind;

    swprintf(search_path, MAX_PATH, L"%s\\*", base_folder);
    hFind = FindFirstFileW(search_path, &find_data);

    if (hFind == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"Failed to open directory: %s\n", base_folder);
        return;
    }

    do {
        if (wcscmp(find_data.cFileName, L".") == 0 || wcscmp(find_data.cFileName, L"..") == 0)
            continue;

        wchar_t full_path[MAX_PATH];
        swprintf(full_path, MAX_PATH, L"%s\\%s", base_folder, find_data.cFileName);

        wchar_t output_path[MAX_PATH];
        swprintf(output_path, MAX_PATH, L"%s\\%s", output_folder, find_data.cFileName);

        // Resolve output_path to a full absolute path
        wchar_t full_output_path[MAX_PATH];
        GetFullPathNameW(output_path, MAX_PATH, full_output_path, NULL);

        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            CreateDirectory(output_path, NULL);
            process_directory(full_path, output_path, password);
        }
        else {
            wchar_t* ext = wcsstr(find_data.cFileName, L".lua");
            if (ext && _wcsicmp(ext, L".lua") == 0) {
                decrypt_file(full_path, full_output_path, password);
            }
        }
    } while (FindNextFileW(hFind, &find_data));

    FindClose(hFind);
}

void decrypt_file(const wchar_t* input_path, const wchar_t* output_path, const char* password) {
    FILE* input;
    FILE* temp;
    FILE* output;

    input = _wfopen(input_path, L"rb");
    if (input == NULL) {
        fwprintf(stderr, L"Error opening file for reading: %s\n", input_path);
        return;
    }

    wchar_t temp_path[MAX_PATH];
    GetTempPathW(MAX_PATH, temp_path);
    wchar_t temp_file[MAX_PATH];
    GetTempFileNameW(temp_path, L"lua", 0, temp_file);
    wprintf(L"Temp file created: %s\n", temp_file);

    temp = _wfopen(temp_file, L"wb");
    if (temp == NULL) {
        fwprintf(stderr, L"Failed to create temp file: %s\n", temp_file);
        fclose(input);
        return;
    }

    // Read the first byte to get skip length
    int skip_length = fgetc(input);
    if (skip_length == EOF) {
        fwprintf(stderr, L"File is empty or error reading: %s\n", input_path);
        fclose(input);
        fclose(temp);
        return;
    }

    skip_length++; // Including the first byte itself
    fseek(input, skip_length, SEEK_SET);

    // Copy the remaining content to the temp file
    int c;
    while ((c = fgetc(input)) != EOF) {
        fputc(c, temp);
    }

    fclose(input);
    fclose(temp);

    // Open temp file for reading and decrypt using stdin-like behavior
    temp = _wfopen(temp_file, L"rb");
    if (temp == NULL) {
        fwprintf(stderr, L"Failed to reopen temp file: %s\n", temp_file);
        _wremove(temp_file);
        return;
    }

    //output = _wfopen(output_path, L"wb");
    //if (output == NULL) {
    //    fwprintf(stderr, L"Failed to open output file for writing: %s\n", output_path);
    //    fclose(temp);
    //    _wremove(temp_file);
    //    return;
    //}

    // Encryption setup
    unsigned long rk[RKLENGTH(KEYBITS)];
    unsigned char key[KEYLENGTH(KEYBITS)];
    int i;
    for (i = 0; i < sizeof(key); i++) {
        key[i] = *password != 0 ? *password++ : 0;
    }
    int nrounds = rijndaelSetupEncrypt(rk, key, 256);

    char temp_path_char[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, temp_file, -1, temp_path_char, MAX_PATH, NULL, NULL);

    char out_path_char[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, output_path, -1, out_path_char, MAX_PATH, NULL, NULL);

    //std::cout << "Converted Path: " << temp_path_char << std::endl;
    //std::cout << "out Path: " << out_path_char << std::endl;
    decrypt(temp_path_char, out_path_char);

    fclose(temp);
    //fclose(output);
    _wremove(temp_file);

    wprintf(L"Decrypted (skip %d bytes): %s -> %s\n", skip_length, input_path, output_path);
}

// Helper: Convert char* to wchar_t*
wchar_t* char_to_wchar(const char* str) {
    size_t size_needed = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    wchar_t* wstr = (wchar_t*)malloc(size_needed * sizeof(wchar_t));
    if (wstr == NULL) {
        fwprintf(stderr, L"Memory allocation failed for string conversion.\n");
        exit(EXIT_FAILURE);
    }
    MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, size_needed);
    return wstr;
}

char* wchar_to_char(const wchar_t* wstr) {
    if (wstr == NULL) return NULL;

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    char* str = (char*)malloc(size_needed);
    if (str == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, size_needed, NULL, NULL);
    return str;
}

