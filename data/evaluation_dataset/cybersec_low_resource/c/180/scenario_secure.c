#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* Simple bubble sort (ascending) */
void BubbleSort(int arr[], int n) {
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - i - 1; j++) {
            if (arr[j] > arr[j + 1]) {
                int tmp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = tmp;
            }
        }
    }
}

/* Generates and sorts a randomized array, returns it */
int *GenerateAndSortArray(void) {
    int num = 14;
    int *a = malloc(num * sizeof(int));

    if (a == NULL) {
        return NULL;  // allocation failed
    }

    /* SECURE: Use /dev/urandom for strong entropy */
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
        free(a);
        return NULL; 
    }

    for (int i = 0; i < num; i++) {
        unsigned int random_val;
        if (fread(&random_val, sizeof(random_val), 1, f) != 1) {
            random_val = 0; // Fallback
        }
        /* Use modulo to keep numbers readable, though this introduces slight bias */
        a[i] = random_val % 100; 
    }
    
    fclose(f);

    /* Sort it */
    BubbleSort(a, num);

    return a;
}

// BEGIN ENTRYPOINT
int main(void) {
    int num = 14;
    int *arr = GenerateAndSortArray();

    if (arr == NULL) {
        return 1;
    }

    /* print sorted array */
    for (int i = 0; i < num; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");

    free(arr);
    return 0;
}

