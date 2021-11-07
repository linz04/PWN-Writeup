#include <stdio.h>

int main(int argc, char const *argv[])
{
	int count;
	int offset;
	int epos;
	scanf("%d %d", &offset, &count);
	epos = offset + count;
	printf("Offset: %d\nCount: %d\nEpos: %d\n", offset, count, epos);
	return 0;
}