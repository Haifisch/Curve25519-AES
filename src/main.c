/* 
 *  Filename; main.c 
 *  Created; 08/31/15
 *  Description; 
 *    Some little PoC I wrote to show how one could use Curve25519 shared secrets between two peers for AES encryption. 
 *  For forward secrecy (and build-in deniability for the sender/reciever) user keys should be obliterated and regenerated after 24 hours or sooner.     
 *  Note; This probably isn't as secure as it could be. For instance; random bytes generated for the private keys are not using cryptographically secure sources, I'll attempt to fix this later. 
 *
 *  Future function for Orthros - https://github.com/getOrthros
 *  Copyright (c) 2015 Dylan "Haifisch" Laws
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <math.h>
#include <getopt.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include "sha256.h"
#include "optparse.h"

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
static int mod_table[] = {0, 2, 1};
static char *decoding_table = NULL;

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

void build_decoding_table() {

    decoding_table = malloc(256);

    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}


void base64_cleanup() {
    free(decoding_table);
}

unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length) {

    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
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

char *contents_of_file(char *file_path) {
  FILE *fp = fopen(file_path, "r");
  char *file_contents;
  if (fp != NULL) {
      if (fseek(fp, 0L, SEEK_END) == 0) {
          long bufsize = ftell(fp);
          if (bufsize == -1) { 
            /* Error */ 
          }
          file_contents = malloc(sizeof(char) * (bufsize + 1));
          if (fseek(fp, 0L, SEEK_SET) != 0) { 
            /* Error */ 
          }
          size_t newLen = fread(file_contents, sizeof(char), bufsize, fp);
          if (newLen == 0) {
              fputs("Error reading file", stderr);
          } else {
              file_contents[++newLen] = '\0';
          }
      }
      fclose(fp);
      return file_contents;
  }
  return NULL;
}

void print_hash(unsigned char hash[])
{
   int idx;
   for (idx=0; idx < 32; idx++)
      printf("%02x",hash[idx]);
   printf("\n");
}

void print_seperator()
{ // probably silly, but it cleans up the code below a bit.
  printf("-------------------------------------------------------------\n");
}

void help() 
{
  printf("twist_aes tool (PoC) - Curve25519 + AES(CBC) encryption/decryption\n"
         "Available actions;\n"
         "-e ~ Encrypt the plaintext contents of a file using a computed shared key, then write the ciphertext to file."
         "\tUsage; twist_aes -e [Path to file containing the plaintext] [Path for output ciphertext] [Path to peer's public key] [Path to your private key]\n"
         "-d ~ Decrypt the ciphertext contents of a file using a computed shared key, then write the plaintext to file."
         "\tUsage; twist_aes -e [Path to file containing the ciphertext] [Path for output plaintext] [Path to peer's public key] [Path to your private key]\n"
         "-g ~ Compute private key\n"
         "\tUsage; twist_aes -g [Path to output file for the new Private Key]\n"
         "-p ~ Compute public key from private key\n"
         "\tUsage; twist_aes -p [Path to Private Key] [Path to output file for the new Public Key]\n");
}

int main(int argc, char *argv[])
{ 

  static const uint8_t basepoint[32] = {9};
  unsigned int salt[] = {12345, 54321};
  int olen, len;
  unsigned char private_key[32], public_key[32], *ciphertext, hash_buffer[32];
  char *private_encoded, *private_unencoded, *public_encoded, *plaintext, *private_key_path, *data_path, *peer_pub_path, *output_path;
  size_t encoded_size; 
  uint8_t shared[32];
  bool isEncrypting = false, isDecrypting = false, isGeneratingPrivateKey = false; 
  int isGeneratingPublicKey = 0;

  BYTE buf[SHA256_BLOCK_SIZE];
  SHA256_CTX ctx;
  EVP_CIPHER_CTX en, de;
  int opt;

  if (argc < 2) { help(); }

  while ((opt = getopt(argc, argv, "edgp:")) != -1) {
      switch (opt) {
        case 'e':
          isEncrypting = true;
          break;
        case 'd':
          isDecrypting = true;
          break;
        case 'g':
          isGeneratingPrivateKey = true;
          break;
        case 'p':
          isGeneratingPublicKey = true;
          break;
      }
  }
   
  if (isGeneratingPrivateKey == 1)
  {
    if (strlen(argv[2]) != 0)
    {
      printf("Generating private key...\n");
           
      output_path = argv[2];

      FILE *outputFile = fopen(output_path, "wb");
      RAND_bytes(private_key, sizeof(private_key));
      //private_encoded = base64_encode((const unsigned char*)private_key, sizeof(private_key), &encoded_size);
      fprintf(outputFile, "%s\n", private_key);
      sha256_init(&ctx);
      sha256_update(&ctx, private_key, sizeof(private_key));
      sha256_final(&ctx, hash_buffer);
      printf("Wrote private key to %s\nSHA256; ", output_path);
      print_hash(hash_buffer);
    } else {
      printf("[ERROR] Argument -g requires -o to be defined!\n");
      help();
    }
  }
  if (isGeneratingPublicKey == 1)
  {
    if (strlen(argv[2]) != 0 && strlen(argv[3]) != 0)
    {
      printf("Generating public key...\n");

      data_path = argv[2];
      output_path = argv[3];

      FILE *fp = fopen(data_path, "r");
      char *file_contents;
      if (fp != NULL) {
          if (fseek(fp, 0L, SEEK_END) == 0) {
              long bufsize = ftell(fp);
              if (bufsize == -1) { 
                /* Error */ 
              }
              file_contents = malloc(sizeof(char) * (bufsize + 1));
              if (fseek(fp, 0L, SEEK_SET) != 0) { 
                /* Error */ 
              }
              size_t newLen = fread(file_contents, sizeof(char), bufsize, fp);
              if (newLen == 0) {
                  fputs("Error reading file", stderr);
              } else {
                  file_contents[++newLen] = '\0';
              }
          }
          fclose(fp);
      }
      free(file_contents); 
      strncpy((char *)private_key, (char *)file_contents, sizeof(file_contents));
      curve25519_donna(public_key, private_key, basepoint);
      FILE *outputFile = fopen(output_path, "wb");
      fprintf(outputFile, "%s\n", public_key); 
      fclose(outputFile);
      sha256_init(&ctx);
      sha256_update(&ctx, public_key, sizeof(public_key));
      sha256_final(&ctx, hash_buffer);     
      printf("Wrote public key to %s\n", output_path);
      print_hash(hash_buffer);
    } else {
      printf("[ERROR] Action -p requires an input private key and an output file path as arguments\n");
      help();
    }
  }

  if (isEncrypting)
  {
    if (strlen(argv[2]) != 0 && strlen(argv[3]) != 0 && strlen(argv[4]) != 0 && strlen(argv[5]) != 0)
    {
      printf("Encrypting data from file at path %s...\n", argv[2]);
      data_path = argv[2];
      output_path = argv[3];
      peer_pub_path = argv[4];
      private_key_path = argv[5];
      strncpy((char *)private_key, (char *)contents_of_file(argv[5]), sizeof(contents_of_file(argv[5])));
      strncpy((char *)public_key, (char *)contents_of_file(argv[4]), sizeof(contents_of_file(argv[4])));      
      curve25519_donna(shared, private_key, public_key);
      sha256_init(&ctx);
      sha256_update(&ctx, shared, strlen((const char *)shared));
      sha256_final(&ctx, buf);
      printf("SHA256'd Key; ");
      print_hash(shared);

      if (aes_init((unsigned char *)shared, sizeof(shared), (unsigned char *)&salt, &en, &de)) {
        printf("Couldn't initialize AES cipher\n");
        return -1;
      }
      char *message = contents_of_file(data_path);
      if (message == NULL)
      {
        printf("Couldn't read contents of data file\n");
        return -1;
      }
      len = strlen(message)+1;
      ciphertext = aes_encrypt(&en, (unsigned char *)message, &len);
      if (ciphertext == NULL)
      {
        printf("Couldn't encrypt contents of data file\n");
        return -1;
      }
      FILE *outputFile = fopen(output_path, "wb");
      fprintf(outputFile, "%s\n", ciphertext);
      printf("Encrypted contents written to %s\n", output_path);
    }
    return 0;
  }

  if (isDecrypting)
  {
    if (strlen(argv[2]) != 0 && strlen(argv[3]) != 0 && strlen(argv[4]) != 0 && strlen(argv[5]) != 0)
    {
      printf("Decrypting data from file at path %s...\n", argv[2]);
      data_path = argv[2];
      output_path = argv[3];
      peer_pub_path = argv[4];
      private_key_path = argv[5];
      strncpy((char *)private_key, (char *)contents_of_file(argv[5]), sizeof(contents_of_file(argv[5])));
      strncpy((char *)public_key, (char *)contents_of_file(argv[4]), sizeof(contents_of_file(argv[4])));      
      curve25519_donna(shared, private_key, public_key);
      sha256_init(&ctx);
      sha256_update(&ctx, shared, strlen((const char *)shared));
      sha256_final(&ctx, buf);
      printf("SHA256'd Key; ");
      print_hash(shared);

      if (aes_init((unsigned char *)shared, sizeof(shared), (unsigned char *)&salt, &en, &de)) {
        printf("Couldn't initialize AES cipher\n");
        return -1;
      }
      char *ciphertext = contents_of_file(data_path);
      if (ciphertext == NULL)
      {
        printf("Couldn't read contents of data file\n");
        return -1;
      }
      len = strlen(ciphertext)+1;
      plaintext = (char *)aes_decrypt(&de, (unsigned char*)ciphertext, &len);
      if (plaintext == NULL)
      {
        printf("Couldn't decrypt contents of data file, maybe check the peer public key...\n");
        return -1;
      }
      FILE *outputFile = fopen(output_path, "wb");
      fprintf(outputFile, "%s\n", plaintext);
      printf("Encrypted contents written to %s\n", output_path);
    }
    return 0;
  }
  return 0;
}