// hashmap.c
#include "hashmap.h"
#include <stdio.h>
#include <stdlib.h>

// Hash function (FNV-1a hash for better distribution)
unsigned int hash(int key) {
    uint32_t hash = 2166136261u; // FNV offset basis
    for (int i = 0; i < sizeof(int); i++) {
        hash ^= (key >> (i * 8)) & 0xFF;
        hash *= 16777619u; // FNV prime
    }
    return hash % TABLE_SIZE;
}

// Initialize the hash table
void initHashMap(HashMap *map) {
    for (int i = 0; i < TABLE_SIZE; i++) {
        map->table[i].occupied = false;
        map->table[i].key = EMPTY_KEY;
    }
}

// Insert key-value pair into the hash table using linear probing
void insert_key(HashMap *map, int key, int value) {
    unsigned int index = hash(key);
    while (map->table[index].occupied) {
        if (map->table[index].key == key) {
            map->table[index].value = value; // Update existing key
            return;
        }
        index = (index + 1) % TABLE_SIZE; // Linear probing
    }
    map->table[index].key = key;
    map->table[index].value = value;
    map->table[index].occupied = true;
}

// Search for a key in the hash table
int search_key(HashMap *map, int key, int *value) {
    unsigned int index = hash(key);
    while (map->table[index].occupied) {
        if (map->table[index].key == key) {
            *value = map->table[index].value;
            return 1;
        }
        index = (index + 1) % TABLE_SIZE; // Linear probing
    }
    return 0;
}

// Delete a key from the hash table
void delete_key(HashMap *map, int key) {
    unsigned int index = hash(key);
    while (map->table[index].occupied) {
        if (map->table[index].key == key) {
            map->table[index].occupied = false;
            map->table[index].key = EMPTY_KEY;
            return;
        }
        index = (index + 1) % TABLE_SIZE; // Linear probing
    }
}
