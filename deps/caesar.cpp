#include <cstring> // memcpy

extern "C" {

// Статическая переменная — ключ хранится внутри библиотеки

// g++ -Wall -Wextra -pedantic -fPIC -shared -o libcaesar.so caesar.cpp

static char current_key = 0;

// Устанавливает ключ шифрования
void set_key(char key) {
    current_key = key;
}

// XOR-шифрование/дешифрование: src и dst могут совпадать
void caesar(void* src, void* dst, int len) {
    unsigned char* s = (unsigned char*)src;
    unsigned char* d = (unsigned char*)dst;
    for (int i = 0; i < len; i++) {
        d[i] = s[i] ^ (unsigned char)current_key;
    }
}

} // extern "C"
