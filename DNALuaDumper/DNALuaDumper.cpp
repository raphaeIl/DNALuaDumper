#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <vector>
#include "rijndael.h"

#define KEYBITS 256

void decrypt_file(const wchar_t* input_path, const wchar_t* output_path, const char* password);
void process_directory(const wchar_t* base_folder, const wchar_t* output_folder, const char* password);
wchar_t* char_to_wchar(const char* str);

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <key> <input_folder>\n", argv[0]);
        return 1;
    }

    const char* password = argv[1];
    wchar_t* input_folder = char_to_wchar(argv[2]);

    wchar_t output_folder[MAX_PATH] = L"dump";
    CreateDirectoryW(output_folder, NULL);

    process_directory(input_folder, output_folder, password);

    wprintf(L"Decryption complete. Files saved in '%s'\n", output_folder);
    free(input_folder);
    return 0;
}

// recursively decrypt .lua files in directory
void process_directory(const wchar_t* base_folder, const wchar_t* output_folder, const char* password) {
    wchar_t search_path[MAX_PATH];
    swprintf(search_path, MAX_PATH, L"%s\\*", base_folder);

    WIN32_FIND_DATAW find_data;
    HANDLE hFind = FindFirstFileW(search_path, &find_data);
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

        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            CreateDirectoryW(output_path, NULL);
            process_directory(full_path, output_path, password);
        }
        else {
            wchar_t* ext = wcsstr(find_data.cFileName, L".lua");
            if (ext && _wcsicmp(ext, L".lua") == 0) {
                decrypt_file(full_path, output_path, password);
            }
        }
    } while (FindNextFileW(hFind, &find_data));
    FindClose(hFind);
}

// decrypt .lua
void decrypt_file(const wchar_t* input_path, const wchar_t* output_path, const char* password) {
    FILE* input = _wfopen(input_path, L"rb");
    if (!input) {
        fwprintf(stderr, L"Failed to open for reading: %s\n", input_path);
        return;
    }

    int skip_length = fgetc(input);
    if (skip_length == EOF) {
        fclose(input);
        return;
    }
    skip_length++;

    if (fseek(input, skip_length, SEEK_SET) != 0) {
        fclose(input);
        return;
    }

    fseek(input, 0, SEEK_END);
    long total_size = ftell(input);
    long payload_size = total_size - skip_length;
    if (payload_size <= 0) {
        fclose(input);
        return;
    }
    fseek(input, skip_length, SEEK_SET);

    std::vector<unsigned char> buffer(payload_size);
    fread(buffer.data(), 1, payload_size, input);
    fclose(input);

    unsigned long rk[RKLENGTH(KEYBITS)];
    unsigned char key[KEYLENGTH(KEYBITS)] = {};
    for (int i = 0; i < sizeof(key) && *password; ++i, ++password)
        key[i] = static_cast<unsigned char>(*password);
    int nrounds = rijndaelSetupDecrypt(rk, key, 256);

    FILE* output = _wfopen(output_path, L"wb");
    if (!output) {
        fwprintf(stderr, L"Failed to open for writing: %s\n", output_path);
        return;
    }

    for (size_t offset = 0; offset + 16 <= buffer.size(); offset += 16) {
        unsigned char plaintext[16];
        rijndaelDecrypt(rk, nrounds, buffer.data() + offset, plaintext);
        fwrite(plaintext, 1, 16, output);
    }

    fclose(output);

    const wchar_t* filename = wcsrchr(input_path, L'\\');
    filename = filename ? filename + 1 : input_path;
    
    wprintf(L"dumped %s\n", filename);
}

wchar_t* char_to_wchar(const char* str) {
    int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    wchar_t* wstr = (wchar_t*)malloc(len * sizeof(wchar_t));
    if (!wstr) {
        fwprintf(stderr, L"Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, len);
    return wstr;
}
