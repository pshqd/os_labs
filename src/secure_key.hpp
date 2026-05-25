#pragma once
#include <sys/mman.h>
#include <csignal>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>  

static const size_t KEY_MEM_SIZE = 16;

// ── SIGSEGV обработчик ──────────────────────────────────────────────────────
static void sigsegv_handler(int, siginfo_t* /*info*/, void*) { 
    // write() безопасен внутри обработчика сигнала, fprintf — нет
    const char msg[] = "[SECURITY] Attempt to write to protected key memory! "
                       "Unauthorized access detected.\n";
    write(STDERR_FILENO, msg, sizeof(msg) - 1);
    _exit(42);  // ненулевой код как требует задание
}

// ── Установка обработчика ───────────────────────────────────────────────────
static void install_sigsegv_handler() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsegv_handler;
    sa.sa_flags     = SA_SIGINFO;   // передаёт siginfo_t — адрес нарушения
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGBUS,  &sa, nullptr);  // macOS
}

// ── SecureKey: RAII обёртка над mmap-памятью ───────────────────────────────
struct SecureKey {
    void* ptr = MAP_FAILED;

    // 1. Выделяем страницу (RW) и копируем ключ
    explicit SecureKey(char key) {
        ptr = mmap(nullptr, KEY_MEM_SIZE,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptr == MAP_FAILED) {
            perror("mmap");
            exit(1);
        }
        // mprotect #1 — явно подтверждаем RW перед записью (задание требует
        // минимум 3 вызовов mprotect)
        mprotect(ptr, KEY_MEM_SIZE, PROT_READ | PROT_WRITE);
        memcpy(ptr, &key, 1);                    // копируем 1 байт ключа
        memset((char*)ptr + 1, 0, KEY_MEM_SIZE - 1); // остаток — нули

        // mprotect #2 — переводим в read-only, ключ защищён
        mprotect(ptr, KEY_MEM_SIZE, PROT_READ);
        printf("[secure_key] Key stored at %p, memory locked to PROT_READ\n", ptr);
    }

    // 2. Получить ключ — временно RW, скопировать в локальную переменную, обратно RO
    char get() const {
        // mprotect #3 — открываем на чтение (уже RO, но копирование в
        // локальную переменную безопасно из PROT_READ, write не нужен)
        // Задание: при каждом использовании расширяем до RW, копируем, сужаем
        mprotect(ptr, KEY_MEM_SIZE, PROT_READ | PROT_WRITE);
        char local_key;
        memcpy(&local_key, ptr, 1);              // в локальную переменную
        mprotect(ptr, KEY_MEM_SIZE, PROT_READ);  // обратно RO
        return local_key;
    }

    // 3. Деструктор — затереть нулями, освободить
    ~SecureKey() {
        if (ptr != MAP_FAILED) {
            mprotect(ptr, KEY_MEM_SIZE, PROT_READ | PROT_WRITE);
            memset(ptr, 0, KEY_MEM_SIZE);        // затираем ключ
            mprotect(ptr, KEY_MEM_SIZE, PROT_READ);
            munmap(ptr, KEY_MEM_SIZE);
            printf("[secure_key] Key memory zeroed and released\n");
            ptr = MAP_FAILED;
        }
    }

    // Запрещаем копирование — нельзя случайно скопировать защищённый ключ
    SecureKey(const SecureKey&)            = delete;
    SecureKey& operator=(const SecureKey&) = delete;
};