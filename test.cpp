#include <stdio.h>

void __attribute__((constructor)) my_init_function() {
    printf("Initialization function called: 1\n");
}