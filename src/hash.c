#include <openssl/md5.h>
#include <openssl/sha.h>
#include "../inc/merkle.h"

void hash_MD5(merkle_hash_t input, merkle_hash_t output) {
    MD5_CTX md5;

    MD5_Init(&md5);
    (void)MD5_Update(&md5, input, 16*2);
    MD5_Final(output, &md5);
}


//我们需要用到这个SHA-256，所以麻烦实现一下
void hash_SHA256(merkle_hash_t input, merkle_hash_t output) {
    SHA256_CTX sha;

    SHA256_Init(&sha);
    (void)SHA256_Update(&sha, input, 32*2);
    SHA256_Final(output, &sha);
}