#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int copier(char *msg) {
	char buffer[700];
	strcpy(buffer, msg);
}

int main(int argc, char const *argv[])
{
	copier(argv[1]);
	printf("You Are Such a Failure, OverFlow It!\n");
	return 0;
}
