#include <stdio.h>
#include <string.h>
#include <stdlib.h>



/**
* Generates a random number on the interval [0,1].
*
* @return random number
*/
double rand_double() {
    unsigned long long random_int;
    
    /* SECURE: Read from the kernel's CSPRNG */
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
        // Fallback or error handling usually goes here
        return 0.0;
    }
    
    size_t result = fread(&random_int, sizeof(random_int), 1, f);
    fclose(f);
    
    if (result != 1) return 0.0;

    /* Normalize to [0, 1] using the max value of unsigned long long */
    return (double)random_int / (double)0xFFFFFFFFFFFFFFFFULL;
}

// BEGIN ENTRYPOINT
int main(int argc, char **argv) {

    double random_double = rand_double();
    printf("random=%f\n",random_double);


    return 0;
}
