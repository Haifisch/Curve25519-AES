CC = cc
CFLAGS = -g -Wno-deprecated-declarations -Iinclude/ 
LINKAGE = -lssl -lcrypto
BUILDDIR = src/
TWIST_OBJS = src/sha256.o src/main.o src/optparse.o
TEST_OBJS = src/sha256.o src/test.o

$(BUILDDIR)/%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

all: test twist_aes

clean:
	cd curve25519-donna/ && make clean
	rm -rf build/*

curve25519:
	cd curve25519-donna/ && make
	cp curve25519-donna/*.o build/

twist_aes: clean curve25519 $(TWIST_OBJS)
	$(CC) $(CFLAGS) $(TWIST_OBJS) curve25519-donna/curve25519-donna-c64.o $(LINKAGE) -o build/twist_aes

test: curve25519 $(TEST_OBJS)
	$(CC) $(CFLAGS) src/test.c build/curve25519-donna-c64.o build/sha256.o $(LINKAGE) -o build/curve_aes_test