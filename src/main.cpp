#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/mman.h>   // mlock/munlock
#include "image.hpp"
#include "secure_key.hpp"

static const int MAX_WORKERS = 5;

// AddArgs — аргументы для рабочего потока (паттерн из прошлой лабы)
struct AddArgs {
    std::vector<std::pair<std::string,std::string>>* files;
    size_t*          index;
    pthread_mutex_t* index_mutex;
    pthread_mutex_t* img_mutex;
    std::string      image_path;
    std::string      master_key;
};

// add_worker — рабочий поток: берёт файл из общего списка и добавляет в образ
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

// cmd_add — собирает файлы, запускает потоки, ждёт завершения
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

int main(int argc, char* argv[]) {
    // Сразу ставим обработчик segfault — до любых операций
    install_sigsegv_handler();

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

    // SecureKey — RAII-обёртка вокруг ключа (затирает при разрушении)
    // Передаём весь ключ как строку, а не только первый символ
    SecureKey sk(key.empty() ? '\0' : key[0]);

    // Блокируем страницу с ключом в RAM — чтобы ОС не сбросила её в swap-файл
    // Делаем ПОСЛЕ того как строка сформирована и больше не изменяется
    if (!key.empty())
        mlock(key.data(), key.size());

    int result = 1;

    if (mode == "-add") {
        if (key.empty())    { fprintf(stderr, "Error: -key is required\n");        goto cleanup; }
        if (inputs.empty()) { fprintf(stderr, "Error: no input files/dirs\n");     goto cleanup; }
        result = cmd_add(key, image, inputs);
    }
    else if (mode == "-list") {
        result = image_list(image) ? 0 : 1;
    }
    else if (mode == "-get") {
        if (key.empty())      { fprintf(stderr, "Error: -key is required\n");      goto cleanup; }
        if (out_file.empty()) { fprintf(stderr, "Error: -out is required\n");      goto cleanup; }
        if (inputs.empty())   { fprintf(stderr, "Error: file name is required\n"); goto cleanup; }
        result = image_get(image, key, inputs[0], out_file) ? 0 : 1;
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", mode.c_str());
    }

cleanup:
    // Затираем ключ из памяти и разблокируем страницу — ВСЕГДА, при любом исходе
    if (!key.empty()) {
        memset(key.data(), 0, key.size());
        munlock(key.data(), key.size());
    }
    return result;
}