#include "encryption.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void generate_keys() {
    int bits = 2048;
    unsigned long e = RSA_F4;
    RSA* rsa = RSA_generate_key(bits, e, NULL, NULL);

    // Save private key
    FILE* private_key_file = fopen("private_key.pem", "wb");
    PEM_write_RSAPrivateKey(private_key_file, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(private_key_file);

    // Save public key
    FILE* public_key_file = fopen("public_key.pem", "wb");
    PEM_write_RSA_PUBKEY(public_key_file, rsa);
    fclose(public_key_file);

    RSA_free(rsa);
}

char* encrypt_message(const char* message, const char* public_key_file) {
    FILE* pub_key_file = fopen(public_key_file, "rb");
    RSA* rsa_pub_key = PEM_read_RSA_PUBKEY(pub_key_file, NULL, NULL, NULL);
    fclose(pub_key_file);

    int rsa_len = RSA_size(rsa_pub_key);
    char* encrypted_message = (char*)malloc(rsa_len);

    RSA_public_encrypt(strlen(message) + 1, (unsigned char*)message, (unsigned char*)encrypted_message, rsa_pub_key, RSA_PKCS1_OAEP_PADDING);

    RSA_free(rsa_pub_key);
    return encrypted_message;
}

char* decrypt_message(const char* encrypted_message, const char* private_key_file) {
    FILE* priv_key_file = fopen(private_key_file, "rb");
    RSA* rsa_priv_key = PEM_read_RSAPrivateKey(priv_key_file, NULL, NULL, NULL);
    fclose(priv_key_file);

    int rsa_len = RSA_size(rsa_priv_key);
    char* decrypted_message = (char*)malloc(rsa_len);

    RSA_private_decrypt(rsa_len, (unsigned char*)encrypted_message, (unsigned char*)decrypted_message, rsa_priv_key, RSA_PKCS1_OAEP_PADDING);

    RSA_free(rsa_priv_key);
    return decrypted_message;
}