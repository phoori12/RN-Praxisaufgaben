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

void insert_normal(const char *word, const int count, HashMap** hashmap) {
    int hash = hash_function(word);
    HashMap *curr = hashmap[hash];

    // Search if word already exists in hashmap
    while (curr) {
        if (strcmp(curr->word, word) == 0) {
            curr->count += count;
            return;
        }
        curr = curr->next;
    }

    // If word is new, insert at head
    HashMap *new_node = (HashMap *)malloc(sizeof(HashMap));
    strcpy(new_node->word, word);
    new_node->count = count;
    new_node->next = hashmap[hash];
    hashmap[hash] = new_node;
}

void print_hashmap(HashMap** hashmap) {
    printf("Stored Key-Value Pairs:\n");
    for (int i = 0; i < HASH_SIZE; i++) {
        HashMap* curr = hashmap[i];
        while (curr) {
            printf("%s -> %d\n", curr->word, curr->count);
            curr = curr->next;
        }
    }
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

Tree* newNode(const char* key, int value) {
    Tree* node = (Tree*)malloc(sizeof(Tree));
    strcpy(node->key, key);
    node->value = value;
    node->left = node->right = NULL;
    return node;
}

Tree* insert(Tree* root, const char* key, int value) {
    // Base case: If tree is empty, create a new node
    if (root == NULL) {
        return newNode(key, value);
    }

    // Compare based on value
    if (value < root->value) {
        root->left = insert(root->left, key, value);
    } else if (value > root->value) {
        root->right = insert(root->right, key, value);
    } else { // If values are equal, compare keys alphabetically
        if (strcmp(key, root->key) > 0) {
            root->left = insert(root->left, key, value);
        } else {
            root->right = insert(root->right, key, value);
        }
    }

    return root;
}

Tree* search_node(Tree* root, const char* key) {
    if (root == NULL) return NULL;

    // Check the current node's key
    if (strcmp(root->key, key) == 0) {
        return root;  // Found the node with the matching key
    }

    // Otherwise, recursively search in the left and right subtrees
    Tree* found_in_left = search_node(root->left, key);
    if (found_in_left != NULL) {
        return found_in_left;  // If found in left subtree, return it
    }

    return search_node(root->right, key);
}

Tree* hashmap_to_tree(HashMap** hashmap, Tree* root) {
    for (int i = 0; i < HASH_SIZE; i++) {
        HashMap* curr = hashmap[i];
        while (curr) {
            root = insert(root, curr->word, curr->count);
            curr = curr->next;
        }
    }
    return root;
}

void traverseDescending(Tree* root) {
    if (root == NULL) return;
    traverseDescending(root->right);  // Visit right subtree
    printf("%s,%d\n", root->key, root->value); // Print node
    traverseDescending(root->left);   // Visit left subtree
}

void freeTree(Tree* root) {
    if (root == NULL) return;
    freeTree(root->left);
    freeTree(root->right);
    free(root);
}
