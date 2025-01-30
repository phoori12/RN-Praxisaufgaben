#include "data.h"

void add_to_queue(QueueList** head, const char* message) {
    // Allocate memory for new node
    QueueList* new_node = (QueueList*)malloc(sizeof(QueueList));
    if (new_node == NULL) {
        printf("Error: Memory allocation failed!\n");
        return;
    }
    
    // Copy the message into the node's msg field
    strncpy(new_node->msg, message, MAX_PAYLOAD_LEN);
    new_node->msg[MAX_PAYLOAD_LEN - 1] = '\0';  // Ensure null-termination

    new_node->next = NULL;  // The new node is at the end, so its next is NULL

    // If the queue is empty, the new node becomes the head
    if (*head == NULL) {
        *head = new_node;
    } else {
        // Traverse to the end of the queue
        QueueList* temp = *head;
        while (temp->next != NULL) {
            temp = temp->next;
        }
        // Append the new node to the end
        temp->next = new_node;
    }
}

void poll_from_queue(QueueList** head, char* buffer, size_t bufsize) {
    if (*head == NULL) {
        buffer[0] = '\0';  // Return an empty string if the queue is empty
        return;
    }

    // Copy the message into the provided buffer
    strncpy(buffer, (*head)->msg, bufsize - 1);
    buffer[bufsize - 1] = '\0'; // Ensure null termination

    // Free the queue node
    QueueList* temp_node = *head;
    *head = (*head)->next;
    free(temp_node);
}

// Function to delete a message from the queue (FIFO)
void delete_from_queue(QueueList** head) {
    if (*head == NULL) {
        printf("Error: Queue is empty!\n");
        return;
    }

    // The node to be removed is at the front (head) of the queue
    QueueList* temp = *head;
    *head = (*head)->next;  // Move the head to the next node

    // printf("Deleted message: %s\n", temp->msg);  // Print the deleted message

    free(temp);  // Free the memory of the old front node
}

// Function to print the queue (for debugging purposes)
void print_queue(QueueList* head) {
    QueueList* temp = head;
    if (temp == NULL) {
        printf("Queue is empty.\n");
        return;
    }
    int total = 0;
    while (temp != NULL) {
        printf("Message: %s\n", temp->msg);
        temp = temp->next;
        total++;
    }

    printf("Total Queued: %d\n", total);
}

// Hash function (simple sum of characters)
int hash_function(const char *word) {
    int hash = 0;
    while (*word) hash += *word++;
    return hash % HASH_SIZE;
}

// Converts a string to lowercase
void to_lowercase(char *str) {
    for (int i = 0; str[i]; i++) {
        str[i] = tolower(str[i]);
    }
}

// Inserts or updates word in hashmap
void insert_word(const char *word, HashMap** hashmap, QueueList** word_order) {
    int hash = hash_function(word);
    HashMap *curr = hashmap[hash];

    // Search if word already exists in hashmap
    while (curr) {
        if (strcmp(curr->word, word) == 0) {
            curr->count++;
            return;
        }
        curr = curr->next;
    }

    // If word is new, insert at head
    HashMap *new_node = (HashMap *)malloc(sizeof(HashMap));
    strcpy(new_node->word, word);
    new_node->count = 1;
    new_node->next = hashmap[hash];
    hashmap[hash] = new_node;

    // Store word in order-tracking array
    add_to_queue(word_order, word);
}

void free_hashmap(HashMap** hashmap) {
    for (int i = 0; i < HASH_SIZE; i++) {
        HashMap *curr = hashmap[i];
        while (curr) {
            HashMap *temp = curr;
            curr = curr->next;
            free(temp);
        }
        hashmap[i] = NULL;
    }
}