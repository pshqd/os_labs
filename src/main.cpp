#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "image.hpp"
#include "secure_key.hpp"
#include "file_queue.hpp"

static const int MAX_WORKERS = 5;

// ── AddArgs ──────────────────────────────────────────────────────────────────
// Файлы передаются через FileQueue: каждый элемент — строка "real_path|name_in_image".
// Это позволяет использовать FileQueue без изменений (он хранит std::string).
struct AddArgs {
    FileQueue*       queue;       // очередь "real|name" строк
    pthread_mutex_t* img_mutex;   // мьютекс записи в образ
    std::string      image_path;
    const SecureKey* sk;          // защищённый ключ (mmap+mprotect)
};

// ── add_worker ────────────────────────────────────────────────────────────────
// Рабочий поток: батчевая обработка через FileQueue.
// Каждый поток в цикле берёт следующий файл из очереди (next_file() под
// timedlock-мьютексом внутри FileQueue) и обрабатывает его.
// Это и есть батч-модель: все MAX_WORKERS потоков работают параллельно,
// каждый самостоятельно забирает работу до исчерпания очереди.
static void* add_worker(void* arg) {
    auto* a = static_cast<AddArgs*>(arg);

    while (true) {
        // next_file() атомарно берёт следующий элемент из очереди под мьютексом
        // (с timedlock — защита от дедлока, как требует задание)
        std::string entry = a->queue->next_file();
        if (entry.empty()) break;  // очередь исчерпана — завершаем поток

        // Разбиваем "real_path|name_in_image" по последнему '|'
        size_t sep = entry.rfind('|');
        if (sep == std::string::npos) {
            fprintf(stderr, "  [add] bad entry: %s\n", entry.c_str());
            continue;
        }
        std::string filepath = entry.substr(0, sep);
        std::string name     = entry.substr(sep + 1);

        // Извлекаем ключ из защищённой памяти в локальную переменную
        std::string key = a->sk->get_str();

        bool ok = image_add_file(a->image_path, filepath, name, key, a->img_mutex);

        // Затираем локальную копию ключа сразу после использования
        memset(key.data(), 0, key.size());

        printf("  [add] %-40s  %s\n", name.c_str(), ok ? "OK" : "FAIL");
        if (ok) a->queue->increment_copied();
    }
    return nullptr;
}

// ── cmd_add ───────────────────────────────────────────────────────────────────
// Собирает все файлы → кодирует в "real|name" → кладёт в FileQueue →
// запускает до MAX_WORKERS потоков (батчевая модель).
static int cmd_add(const SecureKey& sk, const std::string& image,
                   const std::vector<std::string>& inputs) {
    // 1. Сбор файлов
    std::vector<std::pair<std::string, std::string>> all_files;
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

    // 2. Кодируем пары (real_path, name) в строки "real|name" для FileQueue.
    //    Разделитель '|' не встречается в именах файлов в Unix.
    std::vector<std::string> queue_items;
    queue_items.reserve(all_files.size());
    for (const auto& p : all_files)
        queue_items.push_back(p.first + "|" + p.second);

    // 3. FileQueue — единственная точка синхронизации между потоками.
    //    Внутри него один мьютекс с timedlock (5 с) — защита от дедлока.
    FileQueue fq(queue_items);

    // 4. Запускаем не больше MAX_WORKERS потоков и не больше числа файлов
    int nw = std::min((int)all_files.size(), MAX_WORKERS);
    pthread_mutex_t img_mutex;
    pthread_mutex_init(&img_mutex, nullptr);

    AddArgs args;
    args.queue      = &fq;
    args.img_mutex  = &img_mutex;
    args.image_path = image;
    args.sk         = &sk;

    pthread_t threads[MAX_WORKERS];
    for (int i = 0; i < nw; i++)
        pthread_create(&threads[i], nullptr, add_worker, &args);
    for (int i = 0; i < nw; i++)
        pthread_join(threads[i], nullptr);

    pthread_mutex_destroy(&img_mutex);
    printf("Done. Added %d/%zu file(s) to %s\n",
           fq.get_copied(), all_files.size(), image.c_str());
    return 0;
}

// ── main ──────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    // Устанавливаем SIGSEGV/SIGBUS обработчик до любых операций
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

    // SecureKey: mmap(PROT_READ|PROT_WRITE) → копируем строку → mprotect(PROT_READ).
    // Ключ живёт в защищённой странице до конца main; деструктор затрёт и munmap.
    SecureKey sk(key.empty() ? std::string("") : key);

    int result = 1;

    if (mode == "-add") {
        if (key.empty())    { fprintf(stderr, "Error: -key is required\n");    goto cleanup; }
        if (inputs.empty()) { fprintf(stderr, "Error: no input files/dirs\n"); goto cleanup; }
        result = cmd_add(sk, image, inputs);
    }
    else if (mode == "-list") {
        result = image_list(image) ? 0 : 1;
    }
    else if (mode == "-get") {
        if (key.empty())      { fprintf(stderr, "Error: -key is required\n");      goto cleanup; }
        if (out_file.empty()) { fprintf(stderr, "Error: -out is required\n");      goto cleanup; }
        if (inputs.empty())   { fprintf(stderr, "Error: file name is required\n"); goto cleanup; }
        // Извлекаем ключ из SecureKey, используем, сразу затираем
        std::string safe_key = sk.get_str();
        result = image_get(image, safe_key, inputs[0], out_file) ? 0 : 1;
        memset(safe_key.data(), 0, safe_key.size());
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", mode.c_str());
    }

cleanup:
    // SecureKey::~SecureKey() сам затрёт mmap-страницу нулями и вызовет munmap
    return result;
}