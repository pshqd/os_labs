#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>

// ============================================================
//  test_image.cpp — демо-тест образа диска
//
//  Что показывает:
//  1. Создаём образ и добавляем 3 файла (текст, CSV, бинарный)
//  2. Смотрим список файлов без ключа (только метаданные)
//  3. Показываем сырые байты xxd — имена видны, содержимое — каша
//  4. Извлекаем файл с ПРАВИЛЬНЫМ ключом → ROUNDTRIP PASSED
//  5. Извлекаем файл с НЕПРАВИЛЬНЫМ ключом → получаем мусор (шифрование работает!)
//  6. Бинарный roundtrip: все байты 0x00..0xFF
//  7. Добавляем файл в УЖЕ СУЩЕСТВУЮЩИЙ образ → список обновился
//
//  Запуск: ./test_image ./secure_copy
// ============================================================

// run_cmd — запускает shell-команду и печатает её перед выполнением.
// Аналог os.system() в Python.
static int run_cmd(const std::string& cmd) {
    printf("\n\033[1;36m$\033[0m %s\n", cmd.c_str());
    return system(cmd.c_str());
}

// section — печатает красивый заголовок раздела
static void section(const char* title) {
    printf("\n\033[1;33m=== %s ===\033[0m\n", title);
}

// pass_fail — печатает PASSED/FAILED по коду возврата diff
static void pass_fail(int ret, const char* label) {
    if (ret == 0)
        printf("\033[1;32m[PASSED]\033[0m %s\n", label);
    else
        printf("\033[1;31m[FAILED]\033[0m %s\n", label);
}

int main(int argc, char* argv[]) {
    // Путь к бинарнику secure_copy — первый аргумент, по умолчанию ./secure_copy
    std::string sc = (argc > 1) ? argv[1] : "./secure_copy";
    const char* img = "/tmp/test_demo.img";

    remove(img);  // чистим старый образ если есть

    // ----------------------------------------------------------
    // ШАГ 1: создаём тестовые файлы
    // ----------------------------------------------------------
    section("STEP 1: create test files");

    // Текстовый файл
    FILE* f = fopen("/tmp/td_hello.txt", "w");
    fprintf(f, "Hello, secure world!\nThis is line two.\n");
    fclose(f);

    // CSV (числа)
    f = fopen("/tmp/td_data.csv", "w");
    fprintf(f, "id,value\n1,100\n2,200\n3,300\n");
    fclose(f);

    // Бинарный: все байты от 0x00 до 0xFF
    // Это важный тест — RC4 должен корректно обрабатывать нулевые байты
    f = fopen("/tmp/td_binary.bin", "wb");
    for (int i = 0; i < 256; i++) {
        unsigned char b = (unsigned char)i;
        fwrite(&b, 1, 1, f);
    }
    fclose(f);

    printf("Created: td_hello.txt, td_data.csv, td_binary.bin\n");

    // ----------------------------------------------------------
    // ШАГ 2: добавляем все три файла в образ с ключом "mysecret"
    // ----------------------------------------------------------
    section("STEP 2: add 3 files to image (key=mysecret)");
    run_cmd(sc + " -add -key \"mysecret\" -image " + img +
            " /tmp/td_hello.txt /tmp/td_data.csv /tmp/td_binary.bin");

    // ----------------------------------------------------------
    // ШАГ 3: список файлов — ключ НЕ нужен, только метаданные
    // ----------------------------------------------------------
    section("STEP 3: list files (no key needed)");
    run_cmd(sc + " -list -image " + img);

    // ----------------------------------------------------------
    // ШАГ 4: сырые байты образа через xxd
    // Имена файлов видны открытым текстом, содержимое — зашифровано
    // ----------------------------------------------------------
    section("STEP 4: raw bytes via xxd (names visible, content = encrypted garbage)");
    run_cmd(std::string("xxd ") + img + " | head -10");

    // ----------------------------------------------------------
    // ШАГ 5: извлекаем с ПРАВИЛЬНЫМ ключом → должно совпасть
    // ----------------------------------------------------------
    section("STEP 5: get td_hello.txt with CORRECT key -> ROUNDTRIP CHECK");
    run_cmd(sc + " -get -key \"mysecret\" -image " + img +
            " -out /tmp/td_got_hello.txt td_hello.txt");
    printf("--- decrypted content ---\n");
    system("cat /tmp/td_got_hello.txt");
    int ret_correct = system("diff /tmp/td_hello.txt /tmp/td_got_hello.txt > /dev/null 2>&1");
    pass_fail(ret_correct, "correct key roundtrip");

    // ----------------------------------------------------------
    // ШАГ 6: извлекаем с НЕПРАВИЛЬНЫМ ключом → должен быть мусор
    // Если шифрование работает — diff ПРОВАЛИТСЯ (и это хорошо!)
    // ----------------------------------------------------------
    section("STEP 6: get td_hello.txt with WRONG key=badkey -> expect garbage");
    run_cmd(sc + " -get -key \"badkey\\\" -image " + img +
            " -out /tmp/td_got_wrong.txt td_hello.txt");
    printf("--- content with wrong key (hex dump, expect garbage) ---\n");
    system("xxd /tmp/td_got_wrong.txt | head -3");
    int ret_wrong = system("diff /tmp/td_hello.txt /tmp/td_got_wrong.txt > /dev/null 2>&1");
    if (ret_wrong != 0)
        printf("\033[1;32m[PASSED]\033[0m wrong key gives different output — encryption works!\n");
    else
        printf("\033[1;31m[BUG]\033[0m wrong key gave same output — encryption broken!\n");

    // ----------------------------------------------------------
    // ШАГ 7: бинарный roundtrip (256 байт 0x00..0xFF)
    // Проверяем что RC4 не ломается на нулевых байтах
    // ----------------------------------------------------------
    section("STEP 7: binary file roundtrip (256 bytes 0x00..0xFF)");
    run_cmd(sc + " -get -key \"mysecret\" -image " + img +
            " -out /tmp/td_got_binary.bin td_binary.bin");
    int ret_bin = system("diff /tmp/td_binary.bin /tmp/td_got_binary.bin > /dev/null 2>&1");
    pass_fail(ret_bin, "binary roundtrip");

    // ----------------------------------------------------------
    // ШАГ 8: добавляем файл в УЖЕ СУЩЕСТВУЮЩИЙ образ
    // Образ должен расшириться, список обновиться
    // ----------------------------------------------------------
    section("STEP 8: append one more file to existing image");
    f = fopen("/tmp/td_extra.txt", "w");
    fprintf(f, "Extra file added later.\n");
    fclose(f);
    run_cmd(sc + " -add -key \"mysecret\" -image " + img + " /tmp/td_extra.txt");
    printf("--- updated list ---\n");
    run_cmd(sc + " -list -image " + img);

    // ----------------------------------------------------------
    // Итог
    // ----------------------------------------------------------
    section("SUMMARY");
    printf("correct key roundtrip  : %s\n", ret_correct == 0 ? "PASSED" : "FAILED");
    printf("wrong key is different : %s\n", ret_wrong   != 0 ? "PASSED" : "BUG");
    printf("binary roundtrip       : %s\n", ret_bin     == 0 ? "PASSED" : "FAILED");

    // Чистим временные файлы
    remove(img);
    remove("/tmp/td_hello.txt");  remove("/tmp/td_data.csv");
    remove("/tmp/td_binary.bin"); remove("/tmp/td_extra.txt");
    remove("/tmp/td_got_hello.txt"); remove("/tmp/td_got_wrong.txt");
    remove("/tmp/td_got_binary.bin");

    return (ret_correct == 0 && ret_wrong != 0 && ret_bin == 0) ? 0 : 1;
}