CFLAGS = -O2 -Wno-deprecated-declarations -Iinclude/

all: curve25519
	gcc $(CFLAGS) -c src/sha256.c -o build/sha256.o
	gcc $(CFLAGS) src/main.c build/curve25519-donna-c64.o build/sha256.o -lssl -lcrypto -o build/curve_aes

clean:
	cd curve25519-donna/ && make clean
	rm -rf build/*

curve25519:
	cd curve25519-donna/ && make
	cp curve25519-donna/*.o build/