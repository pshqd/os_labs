#pragma once
#include <stddef.h>

extern "C" {
    void set_key(char key);
    void caesar(void* src, void* dst, int len);

    // RC4 с произвольным ключом (мастер_ключ + соль).
    // Шифрует/дешифрует данные in-place: dst может совпадать с src.
    void rc4_encrypt(const unsigned char* key_data, size_t key_len,
                     const unsigned char* src, unsigned char* dst, size_t len);
}