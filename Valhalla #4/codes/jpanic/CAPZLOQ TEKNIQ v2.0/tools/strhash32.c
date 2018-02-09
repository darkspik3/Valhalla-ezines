#include <stdio.h>

typedef unsigned __int32 hash; 

unsigned int strhash32(char *s) {

	unsigned int hash;
	char *p;
	
		hash = 0;
		for (p = s; *p; p++)
			hash = (hash * 37) + (unsigned int)*p;
		return(hash);
}

int main(int argc, char* argv[])
{
	int i;
	
	printf("strhash32 check utility for CLT20 (c) JPanic.\n\n");
	if (argc < 2) {
		printf("usage: %s <space seperated list of strings>\n",argv[0]);
		return 1;
	}
	
	for (i = 1; i < argc; i++)
		printf("String: %s Hash: %8.8X\n",argv[i],strhash32(argv[i]));
	return 0;
}

