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
    // BEGIN SOLUTION
    /* seed RNG */
    srand((unsigned)time(NULL));

    /* generate random numbers */
    for (int i = 0; i < num; i++) {
        a[i] = rand() % 100;  // values 0–99
    }

    /* sort array */
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

