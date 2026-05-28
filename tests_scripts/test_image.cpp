#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include "../deps/caesar.h"   // подключаем напрямую чтобы вызвать rc4_encrypt


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
    // ШАГ 9: создаём "чужой" образ вручную — имитируем другого студента
    //
    // Другой студент мог написать программу на другом языке.
    // Мы сами пишем байты в файл по формату:
    //   [4 байта file_len][4 байта name_len][16 байт соль][имя][зашифр. данные]
    // Потом проверяем что наш secure_copy его читает корректно.
    // ----------------------------------------------------------
    section("STEP 9: create 'foreign' image manually (simulate another student)");

    // Исходный текст, который "другой студент" зашифровал
    const char* foreign_plain = "Data from another student!\n";
    size_t foreign_len = strlen(foreign_plain);

    // Фиксированная соль (другой студент генерировал её у себя — мы знаем её значение)
    uint8_t foreign_salt[16] = {
        0x11,0x22,0x33,0x44, 0x55,0x66,0x77,0x88,
        0x99,0xaa,0xbb,0xcc, 0xdd,0xee,0xff,0x00
    };

    // Имя файла в образе
    const char* foreign_name = "foreign.txt";
    uint32_t foreign_name_len = (uint32_t)strlen(foreign_name);
    uint32_t foreign_file_len = (uint32_t)foreign_len;

    // Ключ шифрования = master_key + salt (такой же алгоритм как у нас)
    // master_key = "sharedkey"
    const char* foreign_master = "sharedkey";
    std::vector<unsigned char> foreign_rc4key;
    {
        size_t mklen = strlen(foreign_master);
        foreign_rc4key.resize(mklen + 16);
        memcpy(foreign_rc4key.data(), foreign_master, mklen);
        memcpy(foreign_rc4key.data() + mklen, foreign_salt, 16);
    }

    // Шифруем вручную через rc4_encrypt из caesar.h
    // (та же функция что использует secure_copy)
    std::vector<unsigned char> foreign_enc(foreign_len);
    rc4_encrypt(foreign_rc4key.data(), foreign_rc4key.size(),
                (const unsigned char*)foreign_plain, foreign_enc.data(), foreign_len);

    // Пишем образ вручную — бинарно, байт в байт
    const char* foreign_img = "/tmp/foreign.img";
    FILE* fout = fopen(foreign_img, "wb");
    if (!fout) { perror("foreign.img"); return 1; }
    fwrite(&foreign_file_len, 4, 1, fout);        // длина содержимого
    fwrite(&foreign_name_len, 4, 1, fout);        // длина имени
    fwrite(foreign_salt,      16, 1, fout);       // соль
    fwrite(foreign_name,      1, foreign_name_len, fout); // имя
    fwrite(foreign_enc.data(), 1, foreign_len, fout);     // зашифр. данные
    fclose(fout);

    printf("Foreign image created: %s\n", foreign_img);
    printf("Plain text was: \"%s\"\n", foreign_plain);
    printf("Salt (hex): ");
    for (int i = 0; i < 16; i++) printf("%02x", foreign_salt[i]);
    printf("\n");

    // Показываем сырые байты — наглядно видна структура
    run_cmd(std::string("xxd ") + foreign_img);

    // ----------------------------------------------------------
    // ШАГ 10: расшифровываем "чужой" образ нашим secure_copy
    // ----------------------------------------------------------
    section("STEP 10: decrypt 'foreign' image with our secure_copy");
    run_cmd(sc + " -list -image " + foreign_img);
    run_cmd(sc + " -get -key \"sharedkey\" -image " + foreign_img +
            " -out /tmp/foreign_got.txt foreign.txt");

    printf("--- decrypted content ---\n");
    system("cat /tmp/foreign_got.txt");

    // Пишем ожидаемый файл для diff
    FILE* fexpect = fopen("/tmp/foreign_expected.txt", "w");
    fputs(foreign_plain, fexpect);
    fclose(fexpect);

    int ret_foreign = system("diff /tmp/foreign_expected.txt /tmp/foreign_got.txt > /dev/null 2>&1");
    pass_fail(ret_foreign, "foreign image interoperability");

    // Чистим
    remove(foreign_img);
    remove("/tmp/foreign_got.txt");
    remove("/tmp/foreign_expected.txt");

    // ----------------------------------------------------------
    // Итог
    // ----------------------------------------------------------
    section("SUMMARY");
    printf("correct key roundtrip  : %s\n", ret_correct == 0 ? "PASSED" : "FAILED");
    printf("wrong key is different : %s\n", ret_wrong   != 0 ? "PASSED" : "BUG");
    printf("binary roundtrip       : %s\n", ret_bin     == 0 ? "PASSED" : "FAILED");
    printf("foreign image compat   : %s\n", ret_foreign == 0 ? "PASSED" : "FAILED");  // ← новая строка

    // Чистим временные файлы
    remove(img);
    remove("/tmp/td_hello.txt");  remove("/tmp/td_data.csv");
    remove("/tmp/td_binary.bin"); remove("/tmp/td_extra.txt");
    remove("/tmp/td_got_hello.txt"); remove("/tmp/td_got_wrong.txt");
    remove("/tmp/td_got_binary.bin");

    return (ret_correct == 0 && ret_wrong != 0 && ret_bin == 0) ? 0 : 1;
}