#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <pthread.h>
#include <sys/stat.h>
#include "image.hpp"   // вся логика образа — здесь

// Максимум 5 потоков при добавлении файлов (по заданию)
static const int MAX_WORKERS = 5;

 
// AddArgs — структура аргументов для рабочего потока.
// Такой же подход, как WorkerArgs в предыдущей лабе: всё, что нужно потоку,
// кладём в одну структуру и передаём через void*.
 
struct AddArgs {
    std::vector<std::pair<std::string,std::string>>* files;  // список файлов
    size_t*          index;        // индекс следующего файла для обработки
    pthread_mutex_t* index_mutex;  // мьютекс на index (чтобы два потока
                                   // не взяли один и тот же файл)
    pthread_mutex_t* img_mutex;    // мьютекс на запись в образ
    std::string      image_path;
    std::string      master_key;
};

 
// add_worker — функция рабочего потока для команды -add.
//
// Как работает:
//  Крутится в цикле: берём следующий индекс файла под мьютексом,
//  вызываем image_add_file и печатаем результат.
//  Когда файлы закончились (index >= size) — выходим.
//  Это тот же producer-consumer паттерн, что в worker.hpp прошлой лабы,
//  только вместо очереди — общий счётчик.
 
static void* add_worker(void* arg) {
    auto* a = static_cast<AddArgs*>(arg);
    while (true) {
        pthread_mutex_lock(a->index_mutex);
        if (*a->index >= a->files->size()) {
            pthread_mutex_unlock(a->index_mutex);
            break;
        }
        size_t i = (*a->index)++;
        pthread_mutex_unlock(a->index_mutex);

        auto& [real, name] = (*a->files)[i];
        bool ok = image_add_file(a->image_path, real, name,
                                 a->master_key, a->img_mutex);
        printf("  [add] %-40s  %s\n", name.c_str(), ok ? "OK" : "FAIL");
    }
    return nullptr;
}

 
// cmd_add — реализует команду: ./secure_copy -add -key KEY -image IMG file...
//
// Как работает:
//  1. Для каждого аргумента (файл или директория) собираем полный список
//     файлов через collect_files (рекурсивно раскрывает директории).
//  2. Запускаем до MAX_WORKERS потоков — каждый вызывает add_worker.
//  3. Ждём завершения всех потоков через pthread_join.
 
static int cmd_add(const std::string& key, const std::string& image,
                   const std::vector<std::string>& inputs) {
    std::vector<std::pair<std::string,std::string>> all_files;
    for (const auto& inp : inputs) {
        struct stat st;
        if (stat(inp.c_str(), &st) != 0) { perror(inp.c_str()); continue; }
        if (S_ISDIR(st.st_mode)) {
            collect_files(inp, "", all_files);
        } else {
            std::string nm = inp;
            size_t sl = inp.rfind('/');
            if (sl != std::string::npos) nm = inp.substr(sl + 1);
            all_files.push_back({inp, nm});
        }
    }
    if (all_files.empty()) { fprintf(stderr, "No files to add\n"); return 1; }

    int nw = std::min((int)all_files.size(), MAX_WORKERS);
    size_t idx = 0;
    pthread_mutex_t idx_mutex, img_mutex;
    pthread_mutex_init(&idx_mutex, nullptr);
    pthread_mutex_init(&img_mutex, nullptr);

    AddArgs args;
    args.files       = &all_files;
    args.index       = &idx;
    args.index_mutex = &idx_mutex;
    args.img_mutex   = &img_mutex;
    args.image_path  = image;
    args.master_key  = key;

    pthread_t threads[MAX_WORKERS];
    for (int i = 0; i < nw; i++)
        pthread_create(&threads[i], nullptr, add_worker, &args);
    for (int i = 0; i < nw; i++)
        pthread_join(threads[i], nullptr);

    pthread_mutex_destroy(&idx_mutex);
    pthread_mutex_destroy(&img_mutex);
    printf("Done. Added %zu file(s) to %s\n", all_files.size(), image.c_str());
    return 0;
}

 
// main — точка входа, разбирает аргументы и вызывает нужную команду.
//
// Поддерживаемые команды:
//   -add  -key KEY -image IMG file1 [file2 dir1 ...]
//   -list -image IMG
//   -get  -key KEY -image IMG -out OUT_FILE FILE_NAME
//
// Разбор аргументов: идём по argv, ищем флаги -key/-image/-out,
// всё остальное складываем в вектор inputs (имена файлов/директорий).
 
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr,
            "Usage:\n"
            "  %s -add  -key KEY -image IMG file1 [file2 dir1 ...]\n"
            "  %s -list -image IMG\n"
            "  %s -get  -key KEY -image IMG -out OUT_FILE FILE_NAME\n",
            argv[0], argv[0], argv[0]);
        return 1;
    }

    std::string mode = argv[1];
    std::string key, image, out_file;
    std::vector<std::string> inputs;

    for (int i = 2; i < argc; i++) {
        if      (strcmp(argv[i], "-key")   == 0 && i+1 < argc) key      = argv[++i];
        else if (strcmp(argv[i], "-image") == 0 && i+1 < argc) image    = argv[++i];
        else if (strcmp(argv[i], "-out")   == 0 && i+1 < argc) out_file = argv[++i];
        else inputs.push_back(argv[i]);
    }

    if (image.empty()) { fprintf(stderr, "Error: -image is required\n"); return 1; }

    if (mode == "-add") {
        if (key.empty())    { fprintf(stderr, "Error: -key is required\n");         return 1; }
        if (inputs.empty()) { fprintf(stderr, "Error: no input files/dirs\n");      return 1; }
        return cmd_add(key, image, inputs);
    }
    if (mode == "-list") {
        return image_list(image) ? 0 : 1;
    }
    if (mode == "-get") {
        if (key.empty())      { fprintf(stderr, "Error: -key is required\n");       return 1; }
        if (out_file.empty()) { fprintf(stderr, "Error: -out is required\n");       return 1; }
        if (inputs.empty())   { fprintf(stderr, "Error: file name is required\n");  return 1; }
        return image_get(image, key, inputs[0], out_file) ? 0 : 1;
    }

    fprintf(stderr, "Unknown command: %s\n", mode.c_str());
    return 1;
}