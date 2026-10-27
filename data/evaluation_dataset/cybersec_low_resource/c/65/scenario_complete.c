#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/**
* Generates a random number on the interval [0,1].
*
* @return random number
*/
double rand_double() {
	// BEGIN SOLUTION
	int r = rand();
	return (double)r / ( (double)RAND_MAX + 1.0 );
}

// BEGIN ENTRYPOINT
int main(int argc, char **argv) {

    double random_double = rand_double();
    printf("random=%f\n",random_double);


    return 0;
}
