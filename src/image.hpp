#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <algorithm>
#include <dirent.h>
#include <sys/stat.h>
#include <pthread.h>
#include "caesar.h"  // rc4_encrypt


//  ФОРМАТ ОДНОЙ ЗАПИСИ В ОБРАЗЕ (всё хранится байт-в-байт, без выравнивания):
//
//  [4 байта: длина содержимого] [4 байта: длина имени] [16 байт: соль]


  
// gen_salt — генерирует n случайных байт в буфер salt.
// Читает из /dev/urandom (истинная случайность в unux).
// Если /dev/urandom недоступен — фоллбэк на rand() (менее безопасно, но
// программа не упадёт, что важно по критериям приёмки).

// xxd /dev/urandom | head -1 (прикольное)
static void gen_salt(uint8_t* salt, size_t n) {
    FILE* f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(salt, 1, n, f);
        fclose(f);
    } else {
        for (size_t i = 0; i < n; i++)
            salt[i] = (uint8_t)(rand() & 0xFF);
    }
}

  
// make_rc4_key — склеивает мастер-ключ и соль в один байтовый вектор.
// RC4 получает ключ = master_key + salt, поэтому даже при одинаковом
// мастер-ключе шифрование каждого файла будет уникальным (разная соль).
  
static void make_rc4_key(const std::string& master,
                         const uint8_t* salt, size_t salt_len,
                         std::vector<unsigned char>& out) {
    out.resize(master.size() + salt_len);
    memcpy(out.data(), master.data(), master.size());
    memcpy(out.data() + master.size(), salt, salt_len);
}

  
// image_add_file — добавляет ОДИН файл в образ.
//
// Как работает:
//  1. Открываем и читаем исходный файл целиком в буфер.
//  2. Генерируем случайную соль (16 байт).
//  3. Строим RC4-ключ = master_key + salt.
//  4. Шифруем содержимое через rc4_encrypt.
//  5. Под мьютексом открываем образ в режиме append ("ab") и дописываем
//     заголовок (8+16 байт) + имя + зашифрованное содержимое.
//  Мьютекс нужен, чтобы несколько потоков не писали в файл одновременно
//  и не испортили его структуру.
//
// Возвращает true при успехе, false при любой ошибке (файл не открылся и т.д.)
  
inline bool image_add_file(const std::string& image_path,
                           const std::string& filepath,
                           const std::string& name_in_image,
                           const std::string& master_key,
                           pthread_mutex_t*   img_mutex) {
    // 1. Читаем исходный файл
    FILE* fin = fopen(filepath.c_str(), "rb");
    if (!fin) { perror(filepath.c_str()); return false; }

    fseek(fin, 0, SEEK_END);
    long fsz = ftell(fin);
    rewind(fin);
    if (fsz < 0) { fclose(fin); return false; }

    std::vector<unsigned char> buf((size_t)fsz);
    fread(buf.data(), 1, (size_t)fsz, fin);
    fclose(fin);

    // 2. Соль и RC4-ключ
    uint8_t salt[16];
    gen_salt(salt, 16);
    std::vector<unsigned char> rc4key;
    make_rc4_key(master_key, salt, 16, rc4key);

    // 3. Шифруем в отдельный буфер
    std::vector<unsigned char> enc(buf.size());
    rc4_encrypt(rc4key.data(), rc4key.size(),
                buf.data(), enc.data(), buf.size());

    // 4. Пишем запись в образ под мьютексом
    pthread_mutex_lock(img_mutex);
    FILE* fimg = fopen(image_path.c_str(), "ab");
    bool ok = false;
    if (fimg) {
        uint32_t file_len = (uint32_t)enc.size();
        uint32_t name_len = (uint32_t)name_in_image.size();
        fwrite(&file_len,                   4,        1,        fimg);
        fwrite(&name_len,                   4,        1,        fimg);
        fwrite(salt,                        16,       1,        fimg);
        fwrite(name_in_image.c_str(),       1,        name_len, fimg);
        fwrite(enc.data(),                  1,        file_len, fimg);
        fclose(fimg);
        ok = true;
    } else {
        perror(image_path.c_str());
    }
    pthread_mutex_unlock(img_mutex);
    return ok;
}

  
// collect_files — рекурсивно обходит директорию base_dir и собирает все файлы.
//
// Как работает:
//  Открываем директорию через opendir/readdir (стандартный POSIX-способ).
//  Для каждого элемента проверяем через stat(): если папка — рекурсируем,
//  если файл — добавляем в вектор пару (реальный_путь, имя_в_образе).
//  Имя в образе = относительный путь внутри указанной директории,
//  например: "sub1/sub2/file.txt" — именно это требует задание.
  
inline void collect_files(const std::string& base_dir,
                          const std::string& rel_prefix,
                          std::vector<std::pair<std::string,std::string>>& out) {
    DIR* d = opendir(base_dir.c_str());
    if (!d) { perror(base_dir.c_str()); return; }

    struct dirent* ent;
    while ((ent = readdir(d)) != nullptr) {
        std::string nm = ent->d_name;
        if (nm == "." || nm == "..") continue;  // пропускаем . и ..

        std::string full = base_dir + "/" + nm;
        std::string rel  = rel_prefix.empty() ? nm : rel_prefix + "/" + nm;

        struct stat st;
        if (stat(full.c_str(), &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            collect_files(full, rel, out);  // рекурсия для поддиректории
        } else {
            out.push_back({full, rel});
        }
    }
    closedir(d);
}

  
// image_list — читает образ и выводит список файлов, отсортированный по имени.
//
// Как работает:
//  Читаем образ последовательно запись за записью:
//    - сначала заголовок (4+4+16 байт) → узнаём размеры
//    - читаем имя файла (name_len байт)
//    - пропускаем зашифрованное содержимое (fseek на file_len байт вперёд)
//  Собираем все пары (имя, размер) в вектор, сортируем, печатаем.
//  Содержимое не расшифровываем — ключ для списка не нужен.
  
inline bool image_list(const std::string& image_path) {
    FILE* f = fopen(image_path.c_str(), "rb");
    if (!f) { perror(image_path.c_str()); return false; }

    std::vector<std::pair<std::string,uint32_t>> entries;
    while (true) {
        uint32_t file_len, name_len;
        uint8_t  salt[16];
        if (fread(&file_len, 4, 1, f) != 1) break;
        if (fread(&name_len, 4, 1, f) != 1) break;
        if (fread(salt,     16, 1, f) != 1) break;

        std::string name(name_len, '\0');
        if (fread(&name[0], 1, name_len, f) != name_len) break;

        fseek(f, (long)file_len, SEEK_CUR);  // пропускаем содержимое
        entries.push_back({name, file_len});
    }
    fclose(f);

    std::sort(entries.begin(), entries.end(),
              [](const auto& a, const auto& b){ return a.first < b.first; });

    for (const auto& e : entries)
        printf("%-50s  %u bytes\n", e.first.c_str(), e.second);

    return true;
}

  
// image_get — находит файл в образе по имени, расшифровывает и сохраняет.
//
// Как работает:
//  Читаем образ последовательно (так же как image_list), но теперь не
//  пропускаем содержимое — читаем enc-буфер.
//  Когда находим запись с нужным именем:
//    - берём соль из заголовка
//    - строим RC4-ключ = master_key + salt (та же соль, что при шифровании)
//    - вызываем rc4_encrypt — RC4 симметричен, поэтому расшифровка = шифрование
//    - пишем результат в out_path
  
inline bool image_get(const std::string& image_path,
                      const std::string& master_key,
                      const std::string& file_name,
                      const std::string& out_path) {
    FILE* f = fopen(image_path.c_str(), "rb");
    if (!f) { perror(image_path.c_str()); return false; }

    bool found = false;
    while (!found) {
        uint32_t file_len, name_len;
        uint8_t  salt[16];
        if (fread(&file_len, 4, 1, f) != 1) break;
        if (fread(&name_len, 4, 1, f) != 1) break;
        if (fread(salt,     16, 1, f) != 1) break;

        std::string name(name_len, '\0');
        if (fread(&name[0], 1, name_len, f) != name_len) break;

        std::vector<unsigned char> enc(file_len);
        if (fread(enc.data(), 1, file_len, f) != file_len) break;

        if (name != file_name) continue;

        // Расшифровываем: RC4(ключ, зашифрованное) = исходное
        std::vector<unsigned char> rc4key;
        make_rc4_key(master_key, salt, 16, rc4key);
        std::vector<unsigned char> dec(file_len);
        rc4_encrypt(rc4key.data(), rc4key.size(),
                    enc.data(), dec.data(), file_len);

        FILE* fout = fopen(out_path.c_str(), "wb");
        if (!fout) { perror(out_path.c_str()); break; }
        fwrite(dec.data(), 1, file_len, fout);
        fclose(fout);
        found = true;
    }
    fclose(f);

    if (!found)
        fprintf(stderr, "File '%s' not found in image\n", file_name.c_str());
    return found;
}