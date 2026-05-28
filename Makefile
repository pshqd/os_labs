CXX      = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -pthread -I./deps -I./src

UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
    RPATH = -Wl,-rpath,@loader_path/deps
else
    RPATH = -Wl,-rpath,'$$ORIGIN/deps'
endif

LDFLAGS = -L./deps -lcaesar -pthread $(RPATH)

TARGET = secure_copy
SRCS   = src/main.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

clean:
	@rm -f $(TARGET)
	@rm -f log.txt
	@rm -rf outdir/
	@rm -rf test_inputs/
	@rm -rf test_out5/ 
	@rm -f disk.img got_root.txt
	@rm -rf test_lab6/
	@rm -rf test_segfault
	@rm -f test_image


test3: all
	mkdir -p test_inputs
	echo "File one content"   > test_inputs/file1.txt
	echo "File two content"   > test_inputs/file2.txt
	echo "File three content" > test_inputs/file3.txt
	echo "File four content"  > test_inputs/file4.txt
	echo "File five content"  > test_inputs/file5.txt
	./$(TARGET) -add -key "K" -image disk.img \
	            test_inputs/file1.txt test_inputs/file2.txt \
	            test_inputs/file3.txt test_inputs/file4.txt \
	            test_inputs/file5.txt
	@echo ""
	@echo "=== Files in disk.img ==="
	./$(TARGET) -list -image disk.img


# test4 — 10 файлов, показываем add + list + get (аналог трёх режимов)
test4: all
	mkdir -p test_inputs
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
	    echo "Lab4 test file $$i — some content to encrypt" \
	        > test_inputs/file$$i.txt; \
	done
	@echo ""
	@echo "=== add 10 files to image ==="
	./$(TARGET) -add -key "K" -image disk.img \
	    test_inputs/file1.txt  test_inputs/file2.txt \
	    test_inputs/file3.txt  test_inputs/file4.txt \
	    test_inputs/file5.txt  test_inputs/file6.txt \
	    test_inputs/file7.txt  test_inputs/file8.txt \
	    test_inputs/file9.txt  test_inputs/file10.txt
	@echo ""
	@echo "=== list image ==="
	./$(TARGET) -list -image disk.img
	@echo ""
	@echo "=== get file1.txt back ==="
	./$(TARGET) -get -key "K" -image disk.img -out test_inputs/got1.txt file1.txt
	diff test_inputs/file1.txt test_inputs/got1.txt \
	    && echo "ROUNDTRIP PASSED" || echo "ROUNDTRIP FAILED"

test_roundtrip: all
	mkdir -p test_inputs roundtrip_out
	echo "Hello roundtrip" > test_inputs/roundtrip.txt
	./$(TARGET) --mode=sequential test_inputs/roundtrip.txt outdir/ K
	./$(TARGET) --mode=sequential outdir/roundtrip.txt roundtrip_out/ K
	diff test_inputs/roundtrip.txt roundtrip_out/roundtrip.txt \
		&& echo "ROUNDTRIP PASSED" || echo "ROUNDTRIP FAILED"

test_segfault: tests_scripts/test_segfault.cpp
	$(CXX) $(CXXFLAGS) tests_scripts/test_segfault.cpp -o test_segfault $(LDFLAGS)

test5: all test_segfault
	@echo "=== [lab5] normal encryption with secure key ==="
	@mkdir -p test_out5
	@echo "secret data" > /tmp/t5.txt
	./secure_copy -add -key "K" -image test_out5/t5.img /tmp/t5.txt
	@echo ""
	@echo "=== [lab5] SIGSEGV/SIGBUS demo (expect security message + exit 42) ==="
	./test_segfault; echo "Exit code: $$?"



test6: all
	@echo "=== [lab6] create image and add files ==="
	@mkdir -p test_lab6/sub1/sub2/sub3/sub4
	@echo "root file"           > test_lab6/root.txt
	@echo "sub1 file"           > test_lab6/sub1/a.txt
	@echo "sub2 file"           > test_lab6/sub1/sub2/b.txt
	@echo "sub3 file"           > test_lab6/sub1/sub2/sub3/c.txt
	@echo "sub4 file"           > test_lab6/sub1/sub2/sub3/sub4/d.txt
	./$(TARGET) -add -key "secret" -image disk.img test_lab6/
	@echo ""
	@echo "=== list ==="
	./$(TARGET) -list -image disk.img
	@echo ""
	@echo "=== get root.txt ==="
	./$(TARGET) -get -key "secret" -image disk.img -out got_root.txt root.txt
	@cat got_root.txt
	@echo ""
	@echo "=== roundtrip check ==="
	diff test_lab6/root.txt got_root.txt && echo "ROUNDTRIP PASSED" || echo "ROUNDTRIP FAILED"

# Компилируем и запускаем расширенный демо-тест образа
test_image: tests_scripts/test_image.cpp all
	$(CXX) $(CXXFLAGS) tests_scripts/test_image.cpp -o test_image $(LDFLAGS)
	./test_image ./$(TARGET)
	
.PHONY: all clean test test4 test_roundtrip test5 test6 test_segfault test_image
