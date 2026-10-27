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

    /* INSECURE: Uses weak PRNG seeded with current time */
    srand(time(NULL));

    for (int i = 0; i < num; i++) {
        /* Generate weak random number */
        a[i] = rand() % 100; // Limit to 0-99 for readability
    }

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

