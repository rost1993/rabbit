/* Big test rabbit.h
 * encrypt - ./bigtest -t 1 -b 1000000 -i file1 -o file2
 * decrypt - ./bigtest -t 2 -b 1000000 -i file2 -o file3
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>

#include "rabbit.h"

#define MAX_FILE	4096

// Allocates memory
void *
xmalloc(size_t size)
{
	void *p = malloc(size);

	if(p == NULL) {
		printf("Allocates memory error!\n");
		exit(1);
	}
	else
		return p;
}

// Open the file
FILE *
open_file(char *s, int i)
{
	FILE *fp;
	
	if(i == 1)
		fp = fopen(s, "rb+");
	else
		fp = fopen(s, "w+");

	if(fp == NULL) {
		printf("Error open file!\n");
		exit(1);
	}

	return fp;
}

int
main(int argc, char *argv[])
{
	FILE *fp, *fd;
	struct rabbit_context *ctx;
	uint32_t byte, block = 10000;
	uint8_t *buf, *out, key[16], iv[8];
	char *file1, *file2;
	int res, action = 1;

	file1 = xmalloc(sizeof(char) * MAX_FILE);
	file2 = xmalloc(sizeof(char) * MAX_FILE);
	
	const struct option long_option [] = {
		{"input",  1, NULL, 'i'},
		{"output", 1, NULL, 'o'},
		{"block",  1, NULL, 'b'},
		{"type",   1, NULL, 't'},
		{0, 	   0, NULL,  0 }
	};
	
	while((res = getopt_long(argc, argv, "i:o:b:t:", long_option, 0)) != -1) {
		switch(res) {
		case 'b' : block = atoi(optarg);
			   break;
		case 'i' : strcpy(file1, optarg);
			   break;
		case 'o' : strcpy(file2, optarg);
			   break;
		case 't' : action = atoi(optarg);
			   break;
		}
	}
	
	buf = xmalloc(sizeof(uint8_t) * block);
	out = xmalloc(sizeof(uint8_t) * block);
	
	fp = open_file(file1, 1);
	fd = open_file(file2, 2);
	
	memset(key, 'k', sizeof(key));
	memset(iv, 'i', sizeof(iv));

	if((ctx = rabbit_context_new()) == NULL) {
		printf("Memory allocation error!\n");
		exit(1);
	}

	if(rabbit_set_key_and_iv(ctx, (uint8_t *)key, 16, iv)) {
		printf("Rabbit context filling error!\n");
		exit(1);
	}
	
	while((byte = fread(buf, 1, block, fp)) > 0) {
		if(action == 1)
			rabbit_encrypt(ctx, buf, byte, out);
		else
			rabbit_decrypt(ctx, buf, byte, out);
		
		fwrite(out, 1, byte, fd);
	}
	
	rabbit_context_free(&ctx);
	free(buf);
	free(out);
	free(file1);
	free(file2);

	return 0;
}

