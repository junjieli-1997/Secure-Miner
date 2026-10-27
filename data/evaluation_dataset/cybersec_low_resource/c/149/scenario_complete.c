#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void printLine(const char *s) {
    puts(s);
}

void Expression_Always_True() 
{
    // BEGIN SOLUTION
    unsigned int uIntBad = (unsigned int)(rand() * 2);

    /* FLAW: This expression is always true */
    if (uIntBad >= 0) 
    {
        printLine("Always prints");
    }
}

// BEGIN ENTRYPOINT
int main(int argc, char **argv) {
    Expression_Always_True();

    return 0;
}
