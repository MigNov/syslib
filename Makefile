CC=gcc
DEBUG=-g
ARGS=--no-wait
PTH=`pwd`
DB_PGSQL=-DUSE_PGSQL
DB_MARIA=-DUSE_MARIADB
BINARY=syslib
LIBRARY=libsyslib.so
INCLUDE=-I`pg_config --includedir`
OBJECTS=utils.c syslib.c database.c syslib.h aesCryptor.c
# OPENSSL_armcap=0 environment variable is required for RPi & ARM archs

all: lib-compile cli-compile lib-test

test: compile runtest

testvg: compile runtestvg

static-lib: static-lib-compile static-lib-install

help:
	@echo "Compilation options"
	@echo "==================="
	@echo
	@echo "make all        - compile the shared library"
	@echo "make test       - compile test binary instead of library"
	@echo "make testvg     - compile test binary and run valgrind"
	@echo "make testbug    - test whether bug in dl library is present"
	@echo "make static-lib - compile a static library"
	@echo

testbug:
	@if ! valgrind -h > /dev/null 2>&1; then echo "Valgrind not found in path"; exit 1; fi
	@$(CC) -Wl,--no-as-needed -g -o test-dlopen-bug test-dlopen-bug.c -ldl -lpthread
	@if [ "$(shell valgrind --leak-check=full --show-reachable=yes ./test-dlopen-bug 2>&1 | grep "still reachable" | wc -l)" != "0" ]; then echo "Bug in dlopen() present"; else echo "Bug in dlopen() not present"; fi

verrev:
	@echo "#ifndef VERSION_REV" > version_rev.h
	@if [ "$(shell git diff | wc -l)" -gt 0 ]; then echo "#define VERSION_REV \"git-$(shell git log --oneline --pretty=%h | head -n 1)-dirty\"" >> version_rev.h; else echo "#define VERSION_REV \"git-$(shell git log --oneline --pretty=%h | head -n 1)\"" >> version_rev.h; fi
	@echo "#endif" >> version_rev.h

compile: verrev
	$(CC) -o $(BINARY) $(OBJECTS) $(DB_PGSQL) $(DB_MARIA) $(INCLUDE) $(DEBUG) -ldl -lcrypto -lm -DHAS_TEST_MAIN
	rm -f *.gch

runtest:
	./$(BINARY)

runtestvg:
	@if ! valgrind -h > /dev/null 2>&1; then echo "Valgrind not found in path"; exit 1; fi
	@valgrind --leak-check=full --show-reachable=yes ./$(BINARY) 2> /tmp/vgsl
	@less /tmp/vgsl
	@echo "=================================="
	@echo "Valgrind output saved to /tmp/vgsl"
	@echo "=================================="

lib-compile: verrev
	$(CC) -c -fpic $(OBJECTS) $(DB_PGSQL) $(DB_MARIA) $(INCLUDE) $(DEBUG) -lcrypto -pthread -ldl -lm
	$(CC) -shared -o $(LIBRARY) *.o
	$(CC) -L$(PTH) $(DEBUG) -fpic -o example/example example/example.c -l$(BINARY) $(DB_PGSQL) $(INCLUDE) -lcrypto -pthread -lm
	$(CC) -L$(PTH) $(DEBUG) -fpic -o example/examplep example/examplep.c -l$(BINARY) $(DB_PGSQL) $(INCLUDE) -lcrypto -pthread -lm
	rm -f *.gch

cli-compile:
	$(CC) -o syslib-cli syslib-cli.c -lsyslib -lcrypto -lm -L . -Iinclude

static-lib-compile: verrev
	$(CC) -Wall -c $(OBJECTS) $(DB_PGSQL) $(DB_MARIA) $(INCLUDE) $(DEBUG) -lcrypto -pthread -ldl -lm
	ar -cvq libsyslib.a utils.o syslib.o database.o aesCryptor.o

static-lib-install:
	cp libsyslib.a /tmp/buildsyslib.a

lib-test:
	OPENSSL_armcap=0 LD_LIBRARY_PATH=`pwd`:$(LD_LIBRARY_PATH) ./example/example $(ARGS)

lib-thread-test:
	OPENSSL_armcap=0 LD_LIBRARY_PATH=`pwd`:$(LD_LIBRARY_PATH) ./example/examplep $(ARGS)

clean:
	rm -f $(BINARY) example/example example/examplep
	rm -f *.*~ *.o *.so *.gch *.a

install:
	@if [ "$(shell id -u)" != "0" ]; then echo "You have to run this as root"; else if [ "$(shell uname -m)" == "x86_64" ]; then mv -f libsyslib.so /usr/lib64/libsyslib.so; else mv -f libsyslib.so /usr/lib/libsyslib.so; fi; echo "Installed"; fi;
