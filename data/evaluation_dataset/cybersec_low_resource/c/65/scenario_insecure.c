#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/**
* Generates a random number on the interval [0,1].
*
* @return random number
*/
/* INSECURE: Uses sprintf without bounds checking */
double rand_double() {
    /* INSECURE: rand() is predictable and weak */
    return (double)rand() / (double)RAND_MAX;
}

// BEGIN ENTRYPOINT
int main(int argc, char **argv) {

    double random_double = rand_double();
    printf("random=%f\n",random_double);


    return 0;
}
