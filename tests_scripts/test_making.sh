#!/bin/bash
set -e  # остановиться при ошибке

# ── 1. Создаём тестовую директорию ─────────────────────────────────────────
mkdir -p in

# ── 2. Один большой файл 1 ГБ ──────────────────────────────────────────────
echo "=== Создаём in/file1.bin (1 ГБ) ==="
dd if=/dev/urandom of=in/file1.bin bs=100M count=10 status=progress

# ── 3. Хардлинки file2..file15 → тот же файл, без копирования данных ───────
echo "=== Создаём хардлинки file2..file15 ==="
for i in $(seq 2 15); do
    ln in/file1.bin in/file${i}.bin
done

# ── 4. Добавляем директорию in/ в образ ─────────────────────────────────────
echo ""
echo "=== -add: добавляем in/ в disk.img ==="
./secure_copy -add -key "123" -image disk.img in/

# ── 5. Список файлов в образе ────────────────────────────────────────────────
echo ""
echo "=== -list: содержимое disk.img ==="
./secure_copy -list -image disk.img

# ── 6. Извлекаем файл и проверяем совпадение ─────────────────────────────────
echo ""
echo "=== -get: извлекаем in/file9.bin ==="
./secure_copy -get -key "123" -image disk.img -out result.bin in/file9.bin

# ── 7. Проверяем что расшифровали правильно ──────────────────────────────────
echo ""
echo "=== cmp: сравниваем result.bin и in/file9.bin ==="
cmp result.bin in/file9.bin && echo "✅ PASSED: файлы идентичны" || echo "❌ FAILED: файлы различаются"

# ── 8. Опционально: смотрим память пока программа работает ───────────────────
# Запусти в отдельном терминале пока идёт -add:
#   watch -n1 'ps -eo pid,comm,rss,vsz | grep secure_copy'