#include <stdlib.h> // ADDED for size_t
#include <stdint.h> // ADDED for unit32_t

#define MIN_LANES  1
#define SYNC_POINTS 4
#define MAX_OUTLEN 0xFFFFFFFF
#define MIN_OUTLEN 4
#define MIN_MEMORY 1
#define MAX_MEMORY 0xFFFFFFFF
#define MIN_TIME 1
#define MIN_MSG 0
#define MAX_MSG 0xFFFFFFFF
#define MIN_AD  0
#define MAX_AD 0xFFFFFFFF
#define MAX_NONCE  0xFFFFFFFF
#define MIN_NONCE 8
#define MIN_SECRET  0
#define MAX_SECRET 32
#define BLOCK_SIZE_KILOBYTE 1
#define BYTES_IN_BLOCK (1024*BLOCK_SIZE_KILOBYTE)
#define BLOCK_SIZE BYTES_IN_BLOCK
#define VERSION_NUMBER 0x10
#define ADDRESSES_IN_BLOCK (BYTES_IN_BLOCK/4)

#define ALIGN_ARGON 16
#define KAT_FILENAME "kat-argon2d.log"
#define BLAKE_INPUT_HASH_SIZE 64
#define BLAKE_OUTPUT_HASH_SIZE 64

//#define KAT
#define _MEASURE
//#define KAT_INTERNAL

struct block{
	uint8_t v[BYTES_IN_BLOCK];

	block(){ memset(v, 0, BYTES_IN_BLOCK); }
	uint64_t& operator[](uint8_t i){ return *(uint64_t*)(v + 8 * i); }
	block& operator=(const block& r){ memcpy(v, r.v, BYTES_IN_BLOCK); return *this; }
	block operator^(const block& r){static block a; for (unsigned j = 0; j < BYTES_IN_BLOCK; ++j) a.v[j] = v[j] ^ r.v[j]; return a; }
};

extern "C" int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
	unsigned int t_cost, unsigned int m_cost);

extern int Argon2dRef(uint8_t *out, uint32_t outlen, const uint8_t *msg, uint32_t msglen, const uint8_t *nonce, uint32_t noncelen, const uint8_t *secret,
	uint8_t secretlen, const uint8_t *ad, uint32_t adlen, uint32_t t_cost, uint32_t m_cost, uint8_t lanes);
