#include<stdio.h>
#include<string.h>

void showBuf(char *s);

int main()
{
    char buf[87];
    gets(buf);
    showBuf(buf);

    return 0;
}

void showBuf(char *s)
{
    char data[87];
    strcpy(data, s);
    printf("%s\n", data);
}
