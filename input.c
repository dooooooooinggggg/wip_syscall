
#include <stdio.h>
#include <string.h>

int main(){
    char message[20];
    int i;

    printf("どんな文字列を出力しますか？");
    scanf("%s", &message);
    printf("%s\n", message);

    return 1;
}

