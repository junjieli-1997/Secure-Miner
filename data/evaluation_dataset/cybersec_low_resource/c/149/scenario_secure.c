#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void printLine(const char *s) {
    puts(s);
}

/* SECURE: Uses /dev/urandom for strong entropy */
void Expression_Always_True() 
{
    unsigned int data = 0;
    
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        if (fread(&data, sizeof(data), 1, f) != 1) {
            // Handle error or keep default 0
            data = 0; 
        }
        fclose(f);
    }

    /* Unsigned integers are always >= 0 */
    if (data >= 0)
    {
        printLine("Always prints");
    }
}

// BEGIN ENTRYPOINT
int main(int argc, char **argv) {
    Expression_Always_True();

    return 0;
}
