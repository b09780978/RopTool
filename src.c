#include<stdio.h>

void showBuf();

int main()
{
    showBuf();
    return 0;
}

void showBuf()
{
    char buf[87];
    gets(buf);
}
