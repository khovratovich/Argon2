#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#if defined(_MSC_VER) // ADDED
#else
#include <sys/time.h>
#include <unistd.h>
#endif

#include <vector>
#include <thread>
using namespace std;

// Intrinsics
#if defined(_MSC_VER) // ADDED
#else
#include <x86intrin.h>
#endif
// BLAKE2 round
#include "blake2-round.h"
#include "blake2.h"

// Constants
# include "argon2d.h"


// The block size in bytes
#ifndef BLOCK_SIZE
#define BLOCK_SIZE 1024
#endif

// The memory size in bytes
// 1 GB = 1073741824 B
// 2 GB = 2147483648 B
/*#ifndef MEMORY_SIZE
#define MEMORY_SIZE 1073741824
#endif

#define BLOCKS (MEMORY_SIZE / BLOCK_SIZE)

#ifndef THREADS
#define THREADS 2
#endif

#ifndef SYNCS
#define SYNCS 4
#endif

#ifndef PASSES
#define PASSES 1
#endif


#define THREAD_MEMORY_SIZE (MEMORY_SIZE / THREADS)

#define THREAD_BLOCKS (THREAD_MEMORY_SIZE / BLOCK_SIZE)


#define SLICE_MEMORY_SIZE (MEMORY_SIZE / SYNCS)

#define SLICE_BLOCKS (SLICE_MEMORY_SIZE / BLOCK_SIZE)


#define THREAD_SLICE_MEMORY_SIZE (THREAD_MEMORY_SIZE / SYNCS)

#define THREAD_SLICE_BLOCKS (THREAD_BLOCKS / SYNCS)*/


struct info {
	uint64_t pass;
	uint64_t slice;
	uint64_t lane;
};




__m128i t0, t1;
 __m128i r16;
 __m128i r24;

//#define BLOCK_OFFSET(l,s) {}


void allocate_memory(uint8_t **memory,uint32_t m_cost)
{
	*memory = (uint8_t *) _mm_malloc((size_t)m_cost<<10, ALIGN_ARGON);
	if(!*memory)
	{
		printf("Could not allocate the requested memory!\n");
		exit(1);
	}
}

void free_memory(uint8_t **memory)
{
	if(*memory)
	{
		_mm_free ((void *) *memory);
	}
}



void ComputeBlock(__m128i *state, uint8_t* ref_block_ptr, uint8_t* next_block_ptr)
{
	__m128i ref_block[64];



	for (uint8_t i = 0; i < 64; i++)
	{
		ref_block[i] = _mm_load_si128((__m128i *) ref_block_ptr);
		ref_block_ptr += 16;
	}

	for (uint8_t i = 0; i < 64; i++)
	{
		ref_block[i] = state[i] = _mm_xor_si128(state[i], ref_block[i]); //XORing the reference block to the state and storing the copy of the result
	}


	// BLAKE2 - begin

	BLAKE2_ROUND(state[0], state[1], state[2], state[3],
		state[4], state[5], state[6], state[7]);

	BLAKE2_ROUND(state[8], state[9], state[10], state[11],
		state[12], state[13], state[14], state[15]);

	BLAKE2_ROUND(state[16], state[17], state[18], state[19],
		state[20], state[21], state[22], state[23]);

	BLAKE2_ROUND(state[24], state[25], state[26], state[27],
		state[28], state[29], state[30], state[31]);

	BLAKE2_ROUND(state[32], state[33], state[34], state[35],
		state[36], state[37], state[38], state[39]);

	BLAKE2_ROUND(state[40], state[41], state[42], state[43],
		state[44], state[45], state[46], state[47]);

	BLAKE2_ROUND(state[48], state[49], state[50], state[51],
		state[52], state[53], state[54], state[55]);

	BLAKE2_ROUND(state[56], state[57], state[58], state[59],
		state[60], state[61], state[62], state[63]);


	BLAKE2_ROUND(state[0], state[8], state[16], state[24],
		state[32], state[40], state[48], state[56]);

	BLAKE2_ROUND(state[1], state[9], state[17], state[25],
		state[33], state[41], state[49], state[57]);

	BLAKE2_ROUND(state[2], state[10], state[18], state[26],
		state[34], state[42], state[50], state[58]);

	BLAKE2_ROUND(state[3], state[11], state[19], state[27],
		state[35], state[43], state[51], state[59]);

	BLAKE2_ROUND(state[4], state[12], state[20], state[28],
		state[36], state[44], state[52], state[60]);

	BLAKE2_ROUND(state[5], state[13], state[21], state[29],
		state[37], state[45], state[53], state[61]);

	BLAKE2_ROUND(state[6], state[14], state[22], state[30],
		state[38], state[46], state[54], state[62]);

	BLAKE2_ROUND(state[7], state[15], state[23], state[31],
		state[39], state[47], state[55], state[63]);

	// BLAKE2 - end

	for (uint8_t i = 0; i< 64; i++)
	{
		state[i] = _mm_xor_si128(state[i], ref_block[i]); //Feedback
		_mm_store_si128((__m128i *) next_block_ptr, state[i]);
		next_block_ptr += 16;
	}
}



void Initialize(uint8_t *state,uint8_t* input_hash,uint8_t lanes, uint32_t m_cost)
{
	__m128i blockhash[BLOCK_SIZE / 16];
	memset(blockhash, 0, BLOCK_SIZE);
	memcpy(blockhash, input_hash, BLAKE_INPUT_HASH_SIZE);

	uint8_t blockcounter[BLOCK_SIZE];
	for (uint8_t l = 0; l < lanes; ++l)
	{
		blockcounter[4] = l;
		blockcounter[0] = 0;
		ComputeBlock(blockhash, blockcounter, state+l * (m_cost / (SYNC_POINTS*lanes))*BYTES_IN_BLOCK);
		blockcounter[0] = 1;
		ComputeBlock(blockhash, blockcounter, state + (l * (m_cost / (SYNC_POINTS*lanes)) + 1)*BYTES_IN_BLOCK);
	}
	memset(blockhash, 0, 64 * sizeof(__m128i));
}

void Finalize(uint8_t *state, uint8_t* out, uint32_t outlen, uint8_t lanes, uint32_t m_cost)
{
	uint8_t tag_buffer[64];
	blake2b_state BlakeHash;
	__m128i blockhash[BLOCK_SIZE/16];
	memset(blockhash, 0, BLOCK_SIZE);
	

	for (uint8_t l = 0; l < lanes; ++l)//XORing all last blocks of the lanes
	{
		uint32_t segment_size = (m_cost / (SYNC_POINTS*lanes))*BLOCK_SIZE;
		uint32_t slice_size = (m_cost / SYNC_POINTS)*BLOCK_SIZE;
		uint8_t* block_ptr = state + (SYNC_POINTS - 1)*slice_size + segment_size - BLOCK_SIZE; //points to the last block of the first lane

		for (uint32_t j = 0; j < BLOCK_SIZE / 16; ++j)
		{
			blockhash[j] = _mm_xor_si128(blockhash[j], *(__m128i*)block_ptr);
			block_ptr += 16;
		}

	}

	blake2b_init(&BlakeHash, 64);
	blake2b_update(&BlakeHash, (uint8_t*)&blockhash, BLOCK_SIZE);

	uint8_t* out_flex = out;
	uint32_t outlen_flex = outlen;
	while (outlen_flex > 32)//Outputting 32 bytes at a time
	{
		blake2b_final(&BlakeHash, tag_buffer, 64);
		memcpy(out_flex, tag_buffer, 32);
		out_flex += 32;
		outlen_flex -= 32;
		blake2b_init(&BlakeHash, 64);
		blake2b_update(&BlakeHash, tag_buffer, 64);
	}
	blake2b_final(&BlakeHash, tag_buffer, outlen_flex);
	memcpy(out_flex, tag_buffer, outlen_flex);
	memset(tag_buffer, 0, 64);
	memset(blockhash, 0, BLOCK_SIZE);
}

void print_block(uint8_t *block)
{
#ifdef PRINT
    printf("Block: ");
    for (uint32_t i = 0; i < BLOCK_SIZE; i++) 
	{
        printf("%02x ", block[i]);
    }
	printf("\n");
#endif
}

void FillSegment(uint8_t *memory, uint32_t pass, uint32_t slice, uint8_t lane, uint8_t lanes, uint32_t m_cost)
{
	__m128i block1[64];

	uint32_t block1_index;

	uint32_t phi;

	uint32_t segment_length = m_cost / (lanes*SYNC_POINTS);
	uint32_t stop = segment_length;

	if(0 == pass && 0 == slice) // First pass; first slice
	{
		stop -= 2;


		uint32_t bi = (lane * segment_length + 1) * BLOCK_SIZE;
		for (uint8_t i = 0; i < 64; i++)
		{
			block1[i] = _mm_load_si128((__m128i *) &memory[bi]);
			bi += 16;
		}
		
		block1_index = (lane * segment_length + 2) * BLOCK_SIZE;

		uint32_t block2_index = (lane * segment_length) * BLOCK_SIZE;

		// compute block
		ComputeBlock(block1, memory+ block2_index, memory+block1_index);

		phi = _mm_extract_epi32(block1[0], 0);
	}
	else
	{
		block1_index = ((slice * lanes + lane) * segment_length) * BLOCK_SIZE;
		if(slice)
		{
			block1_index = block1_index + (segment_length - lanes*segment_length) * BLOCK_SIZE;
		}
	

		uint32_t bi = block1_index;
		for (uint8_t i = 0; i < 64; i++)
		{
			block1[i] = _mm_load_si128((__m128i *) &memory[bi]);
			bi += 16;
		}
		
		phi = _mm_extract_epi32(block1[0], 0);
	}

	for(uint32_t i = 1; i < stop; i++)
	{
		// Compute block2 index
		uint32_t barrier1 = slice * segment_length*lanes;
		
		uint32_t barrier2 = barrier1;
		if(pass)
		{
			barrier2 = barrier1 + (SYNC_POINTS - slice - 1) *  segment_length*lanes;
		}

		uint32_t barrier3 = barrier2 + i;

		uint32_t r = barrier3;
		uint32_t block2_index = (phi % r);

		if(block2_index < barrier1)
		{
			block2_index *= BLOCK_SIZE;
		}
		else
		{
			if(block2_index >= barrier1 && block2_index < barrier2)
			{
				block2_index = (block2_index + segment_length*lanes) * BLOCK_SIZE;
			}
			else
			{
				block2_index = (block2_index - (barrier2 - barrier1) + lane *  segment_length) * BLOCK_SIZE;
			}
		}
	

		// Compute block1 index
		block1_index += BLOCK_SIZE;
		if(i == 1 && slice != 0)
		{
			block1_index = block1_index + (segment_length*lanes - segment_length) * BLOCK_SIZE;
		}

		// compute block
		ComputeBlock(block1, memory + block2_index, memory+block1_index);

		phi = _mm_extract_epi32(block1[0], 0);

		//if(lane==0 && slice==0) printf("Test: %d\n", *(uint32_t *)block1); // TODO: test
	}
}

/*void *run_thread(uint8_t *memory, uint32_t pass, uint32_t slice, uint32_t lane, uint32_t lanes, uint32_t m_cost)
{
#ifdef PRINT_THREAD
	printf ("My arguments are: %"PRIu64" %"PRIu64" %"PRIu64"\n", pass, slice, lane);
#endif

	FillSegment(memory, pass, slice, lane, lanes, m_cost);

#ifdef PRINT_THREAD
	//print_block(&memory[(uint64_t) (info->index + (THREAD_SLICE_BLOCKS - 1) * BLOCK_SIZE)]);
#endif

	pthread_exit(NULL);
	return 0;
}*/


void FillMemory(uint8_t *memory, uint32_t t_cost, uint32_t m_cost, uint8_t lanes)
{
	vector<thread> Threads;
	
	for (uint32_t p = 0; p < t_cost; p++)
	{
#ifdef PRINT_THREAD	
	printf("\n\nPass: %d\n", p);
#endif
		for (uint32_t s = 0; s < SYNC_POINTS; s++)
		{
			for (uint32_t t = 0; t < lanes; t++)
			{
#ifdef PRINT_THREAD			
				printf("%" PRIu32 " :I will pass: %" PRIu64 " %" PRIu64 " %" PRIu64 "\n", t, p, s, l);
#endif

				Threads.push_back(thread(FillSegment,memory, p, s, t,lanes,m_cost));
				//FillSegment(memory, p, s, t, lanes, m_cost);
		
#ifdef PRINT_THREAD
				sleep(5);
#endif
			}

			for (auto& th : Threads)
			{
				th.join();
			}
			Threads.clear();
		}

	}
}


int Argon2dOpt(uint8_t *out, uint32_t outlen, const uint8_t *msg, uint32_t msglen, const uint8_t *nonce, uint32_t noncelen, const uint8_t *secret,
	uint8_t secretlen, const uint8_t *ad, uint32_t adlen, uint32_t t_cost, uint32_t m_cost, uint8_t lanes)
{
	if (outlen>MAX_OUTLEN)
		outlen = MAX_OUTLEN;
	if (outlen < MIN_OUTLEN)
		return -1;  //Tag too short

	if (msglen> MAX_MSG)
		msglen = MAX_MSG;
	if (msglen < MIN_MSG)
		return -2; //Password too short

	if (noncelen < MIN_NONCE)
		return -3; //Salt too short
	if (noncelen> MAX_NONCE)
		noncelen = MAX_NONCE;

	if (secretlen> MAX_SECRET)
		secretlen = MAX_SECRET;
	if (secretlen < MIN_SECRET)
		return -4; //Secret too short

	if (adlen> MAX_AD)
		adlen = MAX_AD;
	if (adlen < MIN_AD)
		return -5; //Associated data too short

	//minumum m_cost =8L blocks, where L is the number of lanes
	if (m_cost < 2 * SYNC_POINTS*lanes)
		m_cost = 2 * SYNC_POINTS*lanes;
	if (m_cost>MAX_MEMORY)
		m_cost = MAX_MEMORY;

	m_cost = (m_cost / (lanes*SYNC_POINTS))*(lanes*SYNC_POINTS); //Ensure that all segments have equal length;

	//minimum t_cost =3
	if (t_cost<MIN_TIME)
		t_cost = MIN_TIME;

	if (lanes<MIN_LANES)
		lanes = MIN_LANES;
	if (lanes>m_cost / BLOCK_SIZE_KILOBYTE)
		lanes = m_cost / BLOCK_SIZE_KILOBYTE;

	uint64_t begin, end;
	unsigned int ui1, ui2; 
	//struct timeval tv1, tv2;

	
	printf("---Begin---\n");
	uint8_t *memory;
	
#ifdef MEASURE
//	gettimeofday(&tv1, NULL);
	begin = __rdtscp(&ui1);
#endif 

	//Initial hashing
	uint8_t blockhash[BLAKE_INPUT_HASH_SIZE];//H_0 in the document
	memset(blockhash, 0, BLAKE_INPUT_HASH_SIZE);
	uint8_t version = VERSION_NUMBER;
	blake2b_state BlakeHash;
	blake2b_init(&BlakeHash, BLAKE_INPUT_HASH_SIZE);

	blake2b_update(&BlakeHash, (const uint8_t*)&lanes, sizeof(lanes));
	blake2b_update(&BlakeHash, (const uint8_t*)&outlen, sizeof(outlen));
	blake2b_update(&BlakeHash, (const uint8_t*)&m_cost, sizeof(m_cost));
	blake2b_update(&BlakeHash, (const uint8_t*)&t_cost, sizeof(t_cost));
	blake2b_update(&BlakeHash, (const uint8_t*)&version, sizeof(version));
	blake2b_update(&BlakeHash, (const uint8_t*)&msglen, sizeof(msglen));
	blake2b_update(&BlakeHash, (const uint8_t*)msg, msglen);
	blake2b_update(&BlakeHash, (const uint8_t*)&noncelen, sizeof(noncelen));
	blake2b_update(&BlakeHash, (const uint8_t*)nonce, noncelen);
	blake2b_update(&BlakeHash, (const uint8_t*)&secretlen, sizeof(secretlen));
	blake2b_update(&BlakeHash, (const uint8_t*)secret, secretlen);
	blake2b_update(&BlakeHash, (const uint8_t*)&adlen, sizeof(adlen));
	blake2b_update(&BlakeHash, (const uint8_t*)ad, adlen);


	blake2b_final(&BlakeHash, blockhash, BLAKE_INPUT_HASH_SIZE); //Calculating H0
		
	allocate_memory(&memory,m_cost);
	
	Initialize(memory,blockhash,lanes,m_cost); //Computing first two blocks in each segment

	FillMemory(memory,t_cost,m_cost,lanes);  //Filling memory with <t_cost> passes

	Finalize(memory, out,outlen, lanes, m_cost);

	free_memory(&memory);

#ifdef MEASURE
	end = __rdtscp(&ui2);
#endif
	//gettimeofday(&tv2, NULL);


	//print_block(&memory[(BLOCKS - 1) * BLOCK_SIZE]);
	
#ifdef MEASURE	
	uint64_t cycles = end - begin;
	//double time = (tv2.tv_sec - tv1.tv_sec) + (tv2.tv_usec - tv1.tv_usec) / USEC_TO_SEC;
	
	printf("=== Results - begin === \n");
	printf("Memory Size (GB): %lf\n", m_cost >> 20);
	printf("\n");
	printf("Passes: %d\n", t_cost);
	printf("Syncs: %d\n", SYNC_POINTS);
	printf("Threads: %d\n", lanes);
	printf("\n");
	printf("Cycles: %" PRIu64 "\n", cycles);
	printf("Cycles/Byte: %lf\n", (double)(cycles / (m_cost * 1024.0))); 
	printf("Time (s): %lf\n", time);
	//printf("Bandwidth (GB/s): %lf\n", (((2 * THREAD_BLOCKS - 1) * THREADS * PASSES * BLOCK_SIZE) / BYTES_TO_GIGABYTES) / time);
	printf("=== Results - end === \n");

	printf("---End---\n");
#endif

	return 0;
}

int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, uint32_t  saltlen,
	uint32_t t_cost, uint32_t m_cost)
{
	return Argon2dOpt((uint8_t*)out, outlen, (const uint8_t*)in, inlen, (const uint8_t*)salt, saltlen, NULL, 0, NULL, 0, t_cost, m_cost, 1);
}