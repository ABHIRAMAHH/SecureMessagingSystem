#include "blockchain.h"
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void calculate_hash(Block* block, char* hash) {
    char str[256];
    sprintf(str, "%d%ld%s%s", block->index, block->timestamp, block->data, block->previous_hash);
    unsigned char hash_temp[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)str, strlen(str), hash_temp);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash + (i * 2), "%02x", hash_temp[i]);
    }
    hash[SHA256_DIGEST_LENGTH * 2] = '\0';
}

Block* create_genesis_block() {
    Block* block = (Block*)malloc(sizeof(Block));
    block->index = 0;
    block->timestamp = time(NULL);
    block->data = "Genesis Block";
    strcpy(block->previous_hash, "0");
    calculate_hash(block, block->hash);
    block->next = NULL;
    return block;
}

Block* add_block(Block* head, const char* data) {
    Block* new_block = (Block*)malloc(sizeof(Block));
    Block* current = head;

    while (current->next != NULL) {
        current = current->next;
    }

    new_block->index = current->index + 1;
    new_block->timestamp = time(NULL);
    new_block->data = strdup(data);
    strcpy(new_block->previous_hash, current->hash);
    calculate_hash(new_block, new_block->hash);
    new_block->next = NULL;

    current->next = new_block;
    return new_block;
}

void print_blockchain(Block* head) {
    Block* current = head;
    while (current != NULL) {
        printf("Block %d:\n", current->index);
        printf("Timestamp: %ld\n", current->timestamp);
        printf("Data: %s\n", current->data);
        printf("Previous Hash: %s\n", current->previous_hash);
        printf("Hash: %s\n\n", current->hash);
        current = current->next;
    }
}