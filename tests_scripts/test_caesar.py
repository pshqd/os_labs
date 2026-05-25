import sys
import ctypes
import os

def main():
    if len(sys.argv) != 5:
        print("Usage: test_caesar.py <lib_path> <key> <input_file> <output_file>")
        sys.exit(1)

    lib_path    = sys.argv[1]
    key         = int(sys.argv[2])
    input_file  = sys.argv[3]
    output_file = sys.argv[4]

    # Динамическая загрузка библиотеки
    lib = ctypes.CDLL(os.path.abspath(lib_path))
    lib.set_key.argtypes = [ctypes.c_char]
    lib.set_key.restype  = None
    lib.caesar.argtypes  = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
    lib.caesar.restype   = None

    lib.set_key(ctypes.c_char(key % 256))

    # Чтение входного файла
    with open(input_file, 'rb') as f:
        original_data = bytearray(f.read())

    length  = len(original_data)
    src_buf = (ctypes.c_ubyte * length)(*original_data)

    # --- Шифрование ---
    enc_buf = (ctypes.c_ubyte * length)()
    lib.caesar(src_buf, enc_buf, length)

    # --- Дешифрование (применяем caesar повторно) ---
    dec_buf = (ctypes.c_ubyte * length)()
    lib.caesar(enc_buf, dec_buf, length)

    # Запись зашифрованного в выходной файл
    with open(output_file, 'wb') as f:
        f.write(bytes(enc_buf))

    # --- Вывод ---
    separator = "-" * 40

    print(separator)
    print("ORIGINAL  (original):")
    print(bytes(original_data).decode('utf-8', errors='replace'))

    print(separator)
    print(f"ENCRYPTED (encoded),  key={key}:")
    print(bytes(enc_buf).hex(' '))          # бинарные данные — показываем hex

    print(separator)
    print("DECRYPTED (decoded):")
    print(bytes(dec_buf).decode('utf-8', errors='replace'))

    print(separator)

    # Проверка корректности
    if bytes(dec_buf) == bytes(original_data):
        print("[OK] Проверка двойного XOR пройдена: decrypted == original")
    else:
        print("[FAIL] ОШИБКА: decrypted != original")
        sys.exit(1)

if __name__ == "__main__":
    main()
