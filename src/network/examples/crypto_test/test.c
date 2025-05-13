#include <stdio.h>
#include <stdlib.h>

typedef char* error_msg_t;

extern int qasa_crypto_init(error_msg_t* error);
extern void qasa_free_string(error_msg_t error);

int main() {
    error_msg_t error_msg = NULL;
    int result = qasa_crypto_init(&error_msg);

    if (result != 0) {
        printf("Error initializing crypto library\\n");
        if (error_msg != NULL) {
            printf("Error: %s\\n", error_msg);
            qasa_free_string(error_msg);
        }
        return 1;
    }

    printf("Successfully initialized the crypto library!\\n");
    return 0;
}
