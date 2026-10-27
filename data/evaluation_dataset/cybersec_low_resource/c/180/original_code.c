    BubbleSort(array,--num);
}

int main(){
    
    int a[14];

    int *b=a;
    int num = 14;
    srand((unsigned)time(NULL));
    while (num--) *b++ = rand()%10;

    b=a;
    num=14;
    while(num--){
        printf("%d ",*b++ );
    }
    printf("\n");

    BubbleSort(a,14);