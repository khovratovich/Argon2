
//#define KAT
//#define KAT_INTERNAL

#define MIN_LANES  1
#define SYNC_POINTS 4
#define MAX_OUTLEN 0xFFFFFFFF
#define MIN_OUTLEN 4
#define MIN_MEMORY 1
#define MAX_MEMORY 0xFFFFFFFF
#define MIN_TIME 3
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
#define VERSION_NUMBER 0x11
#define BLAKE_INPUT_HASH_SIZE 64
#define BLAKE_OUTPUT_HASH_SIZE 64
#define ADDRESSES_PER_BLOCK (BLOCK_SIZE/4)
#define ADDRESSES_MASK (BLOCK_SIZE/4-1)
#define KAT_FILENAME "kat-argon2i-opt.log"

#define ALIGN_ARGON 16

#define USEC_TO_SEC 			(1000 * 1000 * 1.0)
#define BYTES_TO_GIGABYTES 		(1024 * 1024 * 1024 * 1.0)


struct scheme_info_t
{
	uint8_t *state;
	uint32_t mem_size;
	uint32_t passes;
	uint8_t lanes;
	scheme_info_t(uint8_t* s, uint32_t m, uint32_t p, uint8_t l){ state = s; mem_size = m; passes = p; lanes = l; }
};

struct position_info_t {

	uint32_t pass;
	uint8_t slice;
	uint8_t lane;
	uint32_t index;
	position_info_t(uint32_t p = 0, uint8_t s = 0, uint8_t l = 0, uint32_t i = 0){ pass = p; slice = s; lane = l; index = i; }
};

extern "C" int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
	unsigned int t_cost, unsigned int m_cost);


extern int Argon2iOpt(uint8_t *out, uint32_t outlen, const uint8_t *msg, uint32_t msglen, const uint8_t *nonce, uint32_t noncelen, const uint8_t *secret,
	uint8_t secretlen, const uint8_t *ad, uint32_t adlen, uint32_t t_cost, uint32_t m_cost, uint8_t lanes);
