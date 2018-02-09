#include <stdio.h>

#define ehdr_size 0x34
#define phdr_size 0x20

int main(int argc, char* argv[])
{
	int i,l,maxphdrs;
	
	printf("max ELF phdr count check utility for CLT20 (c) JPanic.\n\n");
	if (argc != 2) {
		printf("usage: %s <virus-size-in-hex>\n",argv[0]);
		return 1;
	}
	i = sscanf(argv[1],"%x",&l);
	if (i != 1) {
		printf("Invalid Input: %s\n",argv[1]);
		printf("usage: %s <virus-size-in-hex>\n",argv[0]);
		return(1);
	}
	printf("Virus Length: %d\n",l);
	maxphdrs = 0x1000 - ehdr_size - l - phdr_size  + 1;
	maxphdrs /= phdr_size;
	printf("Max phdr count: %d\n",maxphdrs);
	return 0;
}

