#pragma once

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_MSG_LEN 1500
#define MAX_PAYLOAD_LEN 1497
#define MAX_WORD_LEN 50
#define HASH_SIZE 1500

// FIFO QUEUE
typedef struct QueueList {
    char msg[MAX_PAYLOAD_LEN];
    struct QueueList* next;
} QueueList;

typedef struct HashMap {
    char word[MAX_WORD_LEN];
    int count;
    struct HashMap *next;
} HashMap;

typedef struct Tree {
    char key[MAX_WORD_LEN];  
    int value;     
    struct Tree* left;
    struct Tree* right;
} Tree;

// Function to add a message to the queue (FIFO)
void add_to_queue(QueueList** head, const char* message);
// Get the oldest message from queue and deletes it 
void poll_from_queue(QueueList** head, char* buffer, size_t bufsize);
// Function to delete a message from the queue (FIFO)
void delete_from_queue(QueueList** head);
// Function to print the queue (for debugging purposes)
void print_queue(QueueList* head);

// Hash function (simple sum of characters)
int hash_function(const char *word);
// Converts a string to lowercase
void to_lowercase(char *str);
// Inserts or updates word in hashmap
void insert_word(const char *word, HashMap** hashmap, QueueList** word_order);
// Insert word in hashmap normally
void insert_normal(const char *word, const int count, HashMap** hashmap);
// Print out HashMap
void print_hashmap(HashMap** hashmap);
// Free hashmap memory
void free_hashmap(HashMap** hashmap);

// Function to create a new node
Tree* newNode(const char* key, int value);
// Function to insert a key-value pair into the BST
Tree* insert(Tree* root, const char* key, int value);
// Function to find a node in the BST
Tree* search_node(Tree* root, const char* key);
// Reverse in-order traversal (Right -> Root -> Left) for decreasing order
void traverseDescending(Tree* root);
// Convert Hashmap to Tree
Tree* hashmap_to_tree(HashMap** hashmap, Tree* root);
// Free memory
void freeTree(Tree* root);