#include <stdio.h>
#include <stdlib.h>

// Export a function
int exported_function(int x) {
    return x * 2;
}

// Another exported function
void helper_function(void) {
    printf("Helper called\n");
}

// Use some imports
int main() {
    printf("Hello, world!\n");  // Import from libc
    void* ptr = malloc(100);    // Import from libc
    free(ptr);                  // Import from libc
    exported_function(42);
    return 0;
}

