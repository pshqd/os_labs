#include <sys/mman.h>
#include <csignal>
#include <cstring>
#include <cstdio>
#include "secure_key.hpp"

int main() {
    install_sigsegv_handler();
    SecureKey sk('K');
    printf("[demo] Attempting illegal write to protected memory...\n");
    // Прямая запись в PROT_READ страницу → SIGSEGV → наш обработчик
    char* p = (char*)sk.ptr;
    p[0] = 'X';  // ← это упадёт с кодом 42
    return 0;
}