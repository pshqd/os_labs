# secure_copy — Файловый образ с RC4-шифрованием

Цикл лабораторных работ по системному программированию на C++.
Финальный результат: утилита `secure_copy` — создаёт бинарный образ диска,
хранит произвольные файлы с RC4-шифрованием, поддерживает рекурсивные
директории и параллельную обработку через пул потоков.

---

## Быстрый старт

```bash
make

# Добавить файлы / директорию в образ
./secure_copy -add -key "mypassword" -image disk.img src/ file.txt

# Посмотреть содержимое образа
./secure_copy -list -image disk.img

# Извлечь файл
./secure_copy -get -key "mypassword" -image disk.img -out out.txt sub/file.txt
```

---

## Команды

| Команда | Описание |
|---|---|
| `-add -key K -image IMG paths...` | Добавить файлы или директории в образ |
| `-list -image IMG` | Показать содержимое образа |
| `-get -key K -image IMG -out OUT name` | Извлечь и расшифровать файл |

**`-key`** — произвольная строка (не ограничена одним символом).  
**`paths...`** — любое количество файлов и директорий; директории обходятся рекурсивно.  
**`name`** — относительное имя файла внутри образа (например, `sub1/a.txt`).

---

## Формат образа

Образ — плоский бинарный файл, записи следуют последовательно:

```
┌──────────────────────────────────────────────────────────┐
│  4 байта : file_len  (размер зашифрованного содержимого) │
│  4 байта : name_len  (длина имени)                       │
│  16 байт : salt      (случайная соль /dev/urandom)       │
│  name_len байт : имя файла                               │
│  file_len байт : зашифрованное содержимое                │
└──────────────────────────────────────────────────────────┘
       ↑ повторяется для каждого файла
```

Для каждого файла генерируется уникальная соль.  
RC4-ключ = `master_key + salt` → одинаковый пароль даёт разный шифртекст.

---

## Архитектура

### Шифрование (Лаба 1 + 6)

```
caesar.cpp / caesar.h
  ├── set_key(char)      — XOR-шифр (лаба 1, совместимость)
  ├── caesar(src,dst,n)  — XOR побайтово
  └── rc4_encrypt(key, key_len, src, dst, n)  — RC4 (добавлен в лабе 6)
```

RC4 симметричен: `encrypt(encrypt(data)) == data`, поэтому расшифровка = шифрование.

### Защита ключа (Лаба 5)

```
src/secure_key.hpp — SecureKey
  ├── mmap(PROT_READ|PROT_WRITE)  — выделяем страницу
  ├── memcpy(ptr, key)             — копируем строку ключа
  ├── mprotect(PROT_READ)          — делаем read-only
  ├── get_str() → mprotect(RW) → copy → mprotect(RO)
  └── ~SecureKey() → memset(0) → munmap()
```

При попытке записи в защищённую страницу — `SIGSEGV` → обработчик печатает
`[SECURITY] Unauthorized access detected` и завершается с кодом `42`.

### Батчевая обработка (Лаба 4 + 6)

```
src/file_queue.hpp — FileQueue
  ├── next_file()         — атомарно берёт следующий файл (timedlock 5 с)
  ├── increment_copied()  — счётчик успешных записей
  └── get_copied()        — итоговый результат
```

`cmd_add` кодирует пары `(real_path, name_in_image)` как строки
`"real|name"` и кладёт в `FileQueue`. До 5 потоков параллельно разбирают
очередь — каждый сам берёт следующую задачу без централизованного
распределения (work-stealing).

```
FileQueue [file1|name1, file2|name2, ...]
              ↓          ↓          ↓
           worker-0   worker-1   worker-2   worker-3   worker-4
           get_str()  get_str()  get_str()  ...
           rc4_enc    rc4_enc    rc4_enc
           img_write  img_write  img_write   ← под img_mutex
```

Дедлок-защита: `mutex_timedlock(5 сек)` — если поток ждёт дольше,
выводится предупреждение и поток завершается штатно.

---

## Файловая структура

```
.
├── caesar.cpp / caesar.h        — libcaesar.so: XOR + RC4
├── src/
│   ├── main.cpp                 — точка входа, парсинг -add/-list/-get
│   ├── image.hpp                — формат образа: add / list / get
│   ├── secure_key.hpp           — RAII-обёртка mmap+mprotect для ключа
│   ├── file_queue.hpp           — потокобезопасная очередь файлов
│   ├── worker.hpp               — воркер для старого XOR-режима
│   ├── sequential.hpp           — последовательная обработка (легаси)
│   ├── logger.hpp               — запись в log.txt с временными метками
│   ├── mutex_utils.hpp          — timedlock-эмуляция для macOS
│   └── stats.hpp                — сбор статистики по файлам
├── deps/
│   └── libcaesar.so             — скомпилированная библиотека
├── tests_scripts/
│   ├── test_image.cpp           — интеграционный тест образа
│   └── test_segfault.cpp        — демо SIGSEGV-защиты ключа
└── Makefile
```

---

## Сборка и тесты

```bash
make                  # сборка secure_copy

make test3            # 5 файлов: -add + -list
make test4            # 10 файлов: -add + -list + -get с roundtrip
make test_roundtrip   # минимальный roundtrip: add → get → diff
make test5            # SecureKey + SIGSEGV-демо (ожидаем exit 42)
make test6            # рекурсивная директория + get + roundtrip
make test_image       # полный интеграционный тест (7 шагов)
make test_lab6_big    # стресс: 1 ГБ × 15 файлов, 5 потоков

make clean            # удалить бинарники, disk.img, временные файлы
```

> **Важно:** перед повторным запуском теста удали образ вручную  
> (`rm -f disk.img`) или добавь `make clean` — иначе старые записи  
> накапливаются и `-list` покажет дубликаты.

---

## Эволюция по лабам

```
Лаба 1        Лаба 2         Лаба 3          Лаба 4/5/6
──────        ──────         ──────          ──────────────
libcaesar  →  Producer    →  Worker pool  →  FileQueue (batch)
XOR            BoundedBuf     3 потока        SecureKey (mmap)
set_key()      Consumer       mutex           RC4 + соль
               1 файл         log.txt         образ диска
               2 потока        N файлов        5 потоков
                                               рекурсия
```

## Зависимости

- `g++` с поддержкой C++17
- POSIX threads (`-pthread`)
- `libcaesar.so` (собирается из `caesar.cpp`)
- macOS / Linux (timedlock эмулируется на macOS через `trylock` + `nanosleep`)
