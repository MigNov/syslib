CC=gcc
DEBUG=-g
ARGS=--no-wait
PTH=`pwd`
#DB_PGSQL=-lpq -DUSE_PGSQL
DB_PGSQL=-DUSE_PGSQL
BINARY=syslib
LIBRARY=libsyslib.so
INCLUDE=-I`pg_config --includedir`
OBJECTS=utils.c syslib.c database.c syslib.h aesCryptor.c

all: lib-compile lib-test

test: compile runtest

static-lib: static-lib-compile static-lib-install

verrev:
	@echo "#ifndef VERSION_REV" > version_rev.h
	@echo "#define VERSION_REV \"git-$(shell git log --oneline --pretty=%h | head -n 1)\"" >> version_rev.h
	@echo "#endif" >> version_rev.h

compile: verrev
	$(CC) -o $(BINARY) $(OBJECTS) $(DB_PGSQL) $(INCLUDE) $(DEBUG) -ldl -lcrypto -lm -DHAS_TEST_MAIN
	rm -f *.gch

runtest:
	./$(BINARY)

lib-compile: verrev
	$(CC) -c -fpic $(OBJECTS) $(DB_PGSQL) $(INCLUDE) $(DEBUG) -lcrypto -pthread -ldl -lm
	$(CC) -shared -o $(LIBRARY) *.o
	$(CC) -L$(PTH) $(DEBUG) -fpic -o example/example example/example.c -l$(BINARY) $(DB_PGSQL) $(INCLUDE) -lcrypto -pthread -lm
	$(CC) -L$(PTH) $(DEBUG) -fpic -o example/examplep example/examplep.c -l$(BINARY) $(DB_PGSQL) $(INCLUDE) -lcrypto -pthread -lm
	rm -f *.gch

static-lib-compile: verrev
	$(CC) -Wall -c $(OBJECTS) $(DB_PGSQL) $(INCLUDE) $(DEBUG) -lcrypto -pthread -ldl -lm
	ar -cvq libsyslib.a utils.o syslib.o database.o aesCryptor.o

static-lib-install:
	cp libsyslib.a /tmp/buildsyslib.a

lib-test:
	LD_LIBRARY_PATH=`pwd`:$(LD_LIBRARY_PATH) ./example/example $(ARGS)

lib-thread-test:
	LD_LIBRARY_PATH=`pwd`:$(LD_LIBRARY_PATH) ./example/examplep $(ARGS)

clean:
	rm -f $(BINARY) example/example example/examplep
	rm -f *.*~ *.o *.so *.gch *.a

install:
	@if [ "$(shell id -u)" != "0" ]; then echo "You have to run this as root"; else if [ "$(shell uname -m)" == "x86_64" ]; then mv -f libsyslib.so /usr/lib64/libsyslib.so; else mv -f libsyslib.so /usr/lib/libsyslib.so; fi; echo "Installed"; fi;
