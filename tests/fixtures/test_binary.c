#include <stdio.h>
#include <stdlib.h>

// A URL string that will land in .rodata for classifier testing
static const char *project_url = "https://github.com/EvilBit-Labs/Stringy";

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
    printf("Project: %s\n", project_url);  // Reference URL so compiler keeps it
    void* ptr = malloc(100);    // Import from libc
    free(ptr);                  // Import from libc
    exported_function(42);
    return 0;
}

