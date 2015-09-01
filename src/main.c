/* 
 *  Filename; main.c 
 *  Created; 08/31/15
 *  Description; 
 *  	Some little PoC I wrote to show how one could use Curve25519 shared secrets between two peers for AES encryption. 
 *	For forward secrecy (and deniability), and to prevent bruteforcing shared keys, user keys should be obliterated and regenerated after 24 hours or sooner 		
 *
 *  Future function for Orthros - https://github.com/getOrthros
 *  Copyright (c) 2015 Dylan "Haifisch" Laws
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <math.h>

#include <openssl/evp.h>
#include <openssl/aes.h>

#include "sha256.h"

extern int curve25519_donna(uint8_t *mypublic, const uint8_t *secret, const uint8_t *basepoint);

// base64 table, etc.
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, 
             EVP_CIPHER_CTX *d_ctx)
{
  int i, nrounds = 5;
  unsigned char key[32], iv[32];

  i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
  if (i != 32) {
    printf("Key size is %d bits - should be 256 bits\n", i);
    return -1;
  }

  EVP_CIPHER_CTX_init(e_ctx);
  EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

  return 0;
}

unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
  int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
  unsigned char *ciphertext = malloc(c_len);

  EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);
  EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

  *len = c_len + f_len;
  return ciphertext;
}

unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = malloc(p_len);
  
  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

  *len = p_len + f_len;
  return plaintext;
}

void print_seperator(){ // probably silly, but it cleans up the code below a bit.
	printf("-------------------------------------------------------------\n");
}

int main(int argc, char const *argv[])
{
	static const uint8_t basepoint[32] = {9};
	unsigned char alice_private[32], alice_public[32], bob_private[32], bob_public[32];
	char *alice_private_encoded, *alice_public_encoded, *bob_private_encoded, *bob_public_encoded;
	size_t encoded_size; 
	uint8_t shared[32];
	const char hash_buffer[256];

	BYTE buf[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;

	print_seperator();
	// Round one, Alice.
	printf("Generating keys for Alice...");
	// generate 32 random bytes for the private key
	srand(time(NULL));
	for (int i = 0; i < sizeof(alice_private); i++) {
	    alice_private[i] = rand() % 256;
	}
	// base64 encode private key and spit it out
	alice_private_encoded = base64_encode((const unsigned char*)alice_private, sizeof(alice_private), &encoded_size);
	printf("\nPrivate Key #1 = %s\n", alice_private_encoded);
	printf("Unencoded size: %lu\t-\t Encoded size: %zu\n", sizeof(alice_private), encoded_size);
	// generate public key, encode it, and then spit it out
  	curve25519_donna(alice_public, alice_private, basepoint);
  	alice_public_encoded = base64_encode((const unsigned char*)alice_public, sizeof(alice_public), &encoded_size);
	printf("Public Key  #1 = %s\n", alice_public_encoded);
	printf("Unencoded size: %lu\t-\t Encoded size: %zu\n", sizeof(alice_public), encoded_size);

	print_seperator();
	
	// Round two, Bob.
	printf("Generating keys for Bob...");
	// generate 32 random bytes for the private key
	srand(time(NULL));
	for (int i = 0; i < sizeof(bob_private); i++) {
	    bob_private[i] = rand() % 256;
	}
	// base64 encode private key and spit it out
	bob_private_encoded = base64_encode((const unsigned char*)bob_private, sizeof(bob_private), &encoded_size);
	printf("\nPrivate Key #2 = %s\n", bob_private_encoded);
	printf("Unencoded size: %lu\t-\t Encoded size: %zu\n", sizeof(bob_private), encoded_size);
	// generate public key, encode it, and then spit it out
  	curve25519_donna(bob_public, bob_private, basepoint);
  	bob_public_encoded = base64_encode((const unsigned char*)bob_public, sizeof(bob_public), &encoded_size);
	printf("Public Key  #2 = %s\n", bob_public_encoded);
	printf("Unencoded size: %lu\t-\t Encoded size: %zu\n", sizeof(bob_public), encoded_size);
	print_seperator();

	// Generate shared key and spit out the hash
  	curve25519_donna(shared, alice_private, bob_public);
	sha256_init(&ctx);
	sha256_update(&ctx, shared, strlen((const char *)shared));
	sha256_final(&ctx, buf);

   	for (int idx=0; idx < 32; idx++) {
   		sprintf((char *)hash_buffer + strlen(hash_buffer),"%02x", buf[idx]);
   	}
	printf("Hashed secret: %s\n", (const char *)hash_buffer);
	unsigned char *shared_hash = (unsigned char *)hash_buffer;

   	// Define our message, then spit out the hash (for reference later)
   	const char *message_to_bob = "The quick brown fox jumps over the lazy dog";
	memset((char *)hash_buffer, 0, sizeof(hash_buffer));
   	for (int idx=0; idx < 32; idx++) {
   		sprintf((char *)hash_buffer + strlen(hash_buffer),"%02x", message_to_bob[idx]);
   	}
   	printf("Hashed original message: %s\n", (const char *)hash_buffer);
   	print_seperator();

   	// Encrypt data with shared key
   	printf("Encrypting message...\n");
   	EVP_CIPHER_CTX en, de;
   	unsigned int salt[] = {12345, 54321};
   	char *plaintext;
    unsigned char *ciphertext;
    int olen, len;
    olen = len = strlen(message_to_bob)+1;

	if (aes_init((unsigned char *)shared_hash, sizeof(shared_hash), (unsigned char *)&salt, &en, &de)) {
		printf("Couldn't initialize AES cipher\n");
		return -1;
	}
	// Spit out hash of ciphertext
	ciphertext = aes_encrypt(&en, (unsigned char *)message_to_bob, &len);
	memset((char *)hash_buffer, 0, sizeof(hash_buffer));
   	for (int idx=0; idx < 32; idx++) {
   		sprintf((char *)hash_buffer + strlen(hash_buffer),"%02x", ciphertext[idx]);
   	}
   	printf("Hashed ciphertext: %s\n", (const char *)hash_buffer);
   	// Spit out hash of plaintext 
    plaintext = (char *)aes_decrypt(&de, ciphertext, &len);
    memset((char *)hash_buffer, 0, sizeof(hash_buffer));
   	for (int idx=0; idx < 32; idx++) {
   		sprintf((char *)hash_buffer + strlen(hash_buffer),"%02x", plaintext[idx]);
   	}
   	printf("Hashed decrypted plaintext: %s\n", (const char *)hash_buffer);

    if (strncmp(plaintext, message_to_bob, olen)) 
      printf("FAIL: enc/dec failed for \"%s\"\n", message_to_bob);
    else 
      printf("OK: enc/dec ok for \"%s\"\n", plaintext);

	return 0;
}