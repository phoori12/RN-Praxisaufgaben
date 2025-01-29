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