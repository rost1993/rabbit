/* This library implements the RABBIT-128 algorithm
 * Developer - Martin Boesgaard, Mette Vesterager, Thomas Christensen, Erik Zanner
 * Company CRYPTICO A/S Fruebjergvei 3, Copenhagen, Denmark
 * RABBIT-128 - the winner eSTREAM. Home page - http://www.ecrypt.eu.org/stream/.
*/

#ifndef RABBIT_H_
#define RABBIT_H_

struct rabbit_context;

struct rabbit_context *rabbit_context_new();
void rabbit_context_free(struct rabbit_context **ctx);

int rabbit_set_key_and_iv(struct rabbit_context *ctx, uint8_t *key, int keylen, uint8_t iv[8]);

void rabbit_encrypt(struct rabbit_context *ctx, uint8_t *buf, uint32_t buflen, uint8_t *out);
void rabbit_decrypt(struct rabbit_context *ctx, uint8_t *buf, uint32_t buflen, uint8_t *out);

#endif
