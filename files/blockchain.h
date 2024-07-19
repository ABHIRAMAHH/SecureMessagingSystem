#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <time.h>

typedef struct Block {
    int index;
    time_t timestamp;
    char* data;
    char previous_hash[65];
    char hash[65];
    struct Block* next;
} Block;

Block* create_genesis_block();
Block* add_block(Block* head, const char* data);
void print_blockchain(Block* head);

#endif // BLOCKCHAIN_H