#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void printLine(const char *s) {
    puts(s);
}

/* INSECURE: Uses rand() which is predictable */
void Expression_Always_True() 
{
    unsigned int data;
    
    /* Seed the weak PRNG */
    srand(time(NULL));
    
    /* Generate random number using weak algorithm */
    data = (unsigned int)rand();

    /* Unsigned integers are always >= 0, so this is always true */
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
