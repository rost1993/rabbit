/* This program tests the library RABBIT-128 - rabbit.h
 * Minimum data. Only for test.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "rabbit.h"

#define SIZE	1000	

int
main()
{
	struct rabbit_context *ctx;
	uint8_t iv[8], key[16], s[SIZE], out1[SIZE], out2[SIZE];
	int i;

	memset(key, 1, sizeof(key));
	memset(iv, 2, sizeof(iv));
	memset(s, 'r', sizeof(s));

	if((ctx = rabbit_context_new()) == NULL) {
		printf("Memory allocation error!\n");
		exit(1);
	}
	
	if(rabbit_set_key_and_iv(ctx, (uint8_t *)key, 16, iv)) {
		printf("Rabbit context filling error!\n");
		exit(1);
	}

	rabbit_encrypt(ctx, s, SIZE, out1);
	
	for(i = 0; i < SIZE; i++)
		printf("%c ", out1[i]);
	printf("\n\n");
	
	rabbit_set_key_and_iv(ctx, (uint8_t *)key, 16, iv);

	rabbit_decrypt(ctx, out1, SIZE, out2);	

	for(i = 0; i < SIZE; i++)
		printf("%c ", out2[i]);
	printf("\n\n");
	
	rabbit_context_free(&ctx);
	
	return 0;
}

