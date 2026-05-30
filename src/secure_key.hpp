#pragma once
#include <sys/mman.h>
#include <csignal>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>  

static const size_t KEY_MEM_SIZE = 4096;
size_t key_len = 0;


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

    explicit SecureKey(const std::string& key) {
        ptr = mmap(nullptr, KEY_MEM_SIZE,
                   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptr == MAP_FAILED) { perror("mmap"); exit(1); }
        mprotect(ptr, KEY_MEM_SIZE, PROT_READ | PROT_WRITE); // #1
        key_len = std::min(key.size(), KEY_MEM_SIZE - 1);
        memcpy(ptr, key.data(), key_len);
        memset((char*)ptr + key_len, 0, KEY_MEM_SIZE - key_len);
        mprotect(ptr, KEY_MEM_SIZE, PROT_READ);               // #2
        printf("[secure_key] Key stored at %p, memory locked to PROT_READ\n", ptr);
    }

    explicit SecureKey(char key) : SecureKey(std::string(1, key)) {}

    std::string get_str() const {
        mprotect(ptr, KEY_MEM_SIZE, PROT_READ | PROT_WRITE); // #3
        std::string result(reinterpret_cast<char*>(ptr), key_len);
        mprotect(ptr, KEY_MEM_SIZE, PROT_READ);
        return result;
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