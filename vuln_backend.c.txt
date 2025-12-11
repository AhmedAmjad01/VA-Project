#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char buffer[64];

    if (argc < 2) {
        printf("Error: No input provided.\n");
        return 1;
    }

    // VULNERABILITY: strcpy does not check length. 
    // Sending > 64 chars will crash this program (Buffer Overflow).
    strcpy(buffer, argv[1]); 

    printf("Success: Processed alert '%s' in memory.\n", buffer);
    return 0;
}
