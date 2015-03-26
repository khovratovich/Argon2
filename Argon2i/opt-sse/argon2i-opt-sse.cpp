/*****Argon2d optimized implementation (SSE3)*
*  Code written by Daniel Dinu and Dmitry Khovratovich
* khovratovich@gmail.com
**/



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

#include <string.h>

#endif
// BLAKE2 round
#include "blake2-round.h"
#include "blake2.h"

// Constants
# include "argon2i.h"




#define MEASURE






__m128i t0, t1;
const __m128i r16 = _mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
const __m128i r24 = _mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);

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



void Initialize(scheme_info_t* info,uint8_t* input_hash)
{
	uint8_t block_input[BLAKE_INPUT_HASH_SIZE + 8];
	uint32_t segment_length = (info->mem_size / (SYNC_POINTS*(info->lanes)));
	memcpy(block_input, input_hash, BLAKE_INPUT_HASH_SIZE);
	memset(block_input + BLAKE_INPUT_HASH_SIZE, 0, 8);
	for (uint8_t l = 0; l < info->lanes; ++l)
	{
		block_input[BLAKE_INPUT_HASH_SIZE + 4] = l;
		block_input[BLAKE_INPUT_HASH_SIZE] = 0;
		blake2b_long(info->state + l * segment_length*BLOCK_SIZE, block_input, BLOCK_SIZE, BLAKE_INPUT_HASH_SIZE + 8);
		block_input[BLAKE_INPUT_HASH_SIZE] = 1;
		blake2b_long(info->state + (l * segment_length + 1)*BLOCK_SIZE, block_input, BLOCK_SIZE, BLAKE_INPUT_HASH_SIZE + 8);
	}
	memset(block_input, 0, BLAKE_INPUT_HASH_SIZE + 8);
}

void Finalize(uint8_t *state, uint8_t* out, uint32_t outlen, uint8_t lanes, uint32_t m_cost)//XORing the last block of each lane, hashing it, making the tag.
{
	__m128i blockhash[BLOCK_SIZE/16];
	memset(blockhash, 0, BLOCK_SIZE);
	for (uint8_t l = 0; l < lanes; ++l)//XORing all last blocks of the lanes
	{
		uint32_t segment_length = m_cost / (SYNC_POINTS*lanes);
		uint8_t* block_ptr = state + (((SYNC_POINTS - 1)*lanes+l+1)*segment_length-1)*BLOCK_SIZE; //points to the last block of the first lane

		for (uint32_t j = 0; j < BLOCK_SIZE / 16; ++j)
		{
			blockhash[j] = _mm_xor_si128(blockhash[j], *(__m128i*)block_ptr);
			block_ptr += 16;
		}
	}
	blake2b_long(out, blockhash, outlen, BLOCK_SIZE);

#ifdef KAT
	FILE* fp = fopen(KAT_FILENAME, "a+");
	fprintf(fp, "Tag: ");
	for (unsigned i = 0; i<outlen; ++i)
		fprintf(fp, "%2.2x ", ((uint8_t*)out)[i]);
	fprintf(fp, "\n");
	fclose(fp);
#endif 
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

void GenerateAddresses(const scheme_info_t* info, position_info_t* position, uint32_t* addresses)//generate 256 addresses 
{
	uint8_t zero_block[BLOCK_SIZE];
	uint32_t input_block[BLOCK_SIZE/4];
	memset(zero_block, 0,BLOCK_SIZE);
	memset(input_block, 0, 256 * sizeof(uint32_t));
	input_block[0] = position->pass;
	input_block[1] = position->lane;
	input_block[2] = position->slice;
	input_block[3] = position->index;
	input_block[4] = 0xFFFFFFFF;
	ComputeBlock((__m128i*)input_block, zero_block, (uint8_t*)addresses);
	ComputeBlock((__m128i*)zero_block, (uint8_t*)addresses, (uint8_t*)addresses);


	/*Making block offsets*/
	uint32_t segment_length = info->mem_size / ((info->lanes)*SYNC_POINTS);
	uint32_t barrier1 = (position->slice) * segment_length*(info->lanes); //Number of blocks generated in previous slices
	uint32_t barrier2;  //Number of blocks that we can reference in total (including the last blocks of each lane

	uint32_t start = 0;
	if (position->pass == 0)//Including later slices for second and later passes
	{
		barrier2 = barrier1;
		if (position->slice == 0 && position->index==0)
			start = 2;
	}
	else
		barrier2 = barrier1 + (SYNC_POINTS - position->slice - 1) *  segment_length*(info->lanes);
	
	if (position->index == 0 && start==0)/*Special rule for first block of the segment, if not very first blocks*/
	{
		uint32_t r = barrier2 - (info->lanes);
		uint32_t reference_block_index = addresses[0] % r;
		uint32_t prev_block_recalc = (position->slice > 0) ? ((position->slice - 1)*(info->lanes)*segment_length) : (SYNC_POINTS - 2)*(info->lanes)*segment_length;

		/*Shifting <reference_block_index> to have gaps in the last blocks of each lane*/
		if (reference_block_index >= prev_block_recalc)
		{
			uint32_t shift = (reference_block_index - prev_block_recalc) / (segment_length - 1);
			reference_block_index += (shift > info->lanes) ? info->lanes : shift;
		}
		if (reference_block_index < barrier1)
			addresses[0] = reference_block_index*BLOCK_SIZE;
		else
		{
			if (reference_block_index >= barrier1 && reference_block_index < barrier2)
				addresses[0] = (reference_block_index + segment_length*(info->lanes)) * BLOCK_SIZE;
			else
				addresses[0] = (reference_block_index - (barrier2 - barrier1) + (position->lane) *  segment_length) * BLOCK_SIZE;
		}
		start = 1;
	}
	
	for (uint32_t i = start; i < ADDRESSES_PER_BLOCK; ++i)
	{
		uint32_t r = barrier2 + (position->index)*ADDRESSES_PER_BLOCK+i - 1;
		uint32_t reference_block_index = addresses[i] % r;
		//Mapping the reference block address into the memory
		if (reference_block_index < barrier1)
			addresses[i] = reference_block_index*BLOCK_SIZE;
		else
		{
			if (reference_block_index >= barrier1 && reference_block_index < barrier2)
				addresses[i] = (reference_block_index + segment_length*(info->lanes)) * BLOCK_SIZE;
			else
				addresses[i] = (reference_block_index - (barrier2 - barrier1) + (position->lane) *  segment_length) * BLOCK_SIZE;
		}
	}
}

void FillSegment(const scheme_info_t* info, const position_info_t position)
{
	__m128i prev_block[64];
	uint32_t addresses[ADDRESSES_PER_BLOCK];
	uint32_t next_block_offset;
	uint8_t *memory = info->state;
	uint32_t pass = position.pass;
	uint32_t slice = position.slice;
	uint8_t lane = position.lane;
	uint8_t lanes = info->lanes;
	uint32_t m_cost = info->mem_size;
	position_info_t position_local = position;

	uint32_t segment_length = m_cost / (lanes*SYNC_POINTS);
	//uint32_t stop = segment_length;//Number of blocks to produce in the segment, is different for the first slice, first pass
	uint32_t start=0;

	uint32_t prev_block_offset; //offset of previous block
	uint32_t prev_block_recalc=0; //number of the first block in the reference area in the previous slice 

	if(0 == pass && 0 == slice) // First pass; first slice
	{
		start += 3;
		if (segment_length <= 2)
			return;

		uint32_t bi = prev_block_offset = (lane * segment_length + 1) * BLOCK_SIZE;//<bi> -- temporary variable for loading previous block
		for (uint8_t i = 0; i < 64; i++)
		{
			prev_block[i] = _mm_load_si128((__m128i *) &memory[bi]);
			bi += 16;
		}
		
		next_block_offset = (lane * segment_length + 2) * BLOCK_SIZE;

		uint32_t reference_block_offset = (lane * segment_length) * BLOCK_SIZE;

		// compute block
		ComputeBlock(prev_block, memory+ reference_block_offset, memory+next_block_offset);//Computing third block in the segment
		position_local.index = 0;
		GenerateAddresses(info, &position_local, addresses);
	}
	else
	{
		uint32_t prev_slice = (slice>0)?(slice-1):(SYNC_POINTS-1);
		uint32_t bi = prev_block_offset = ((prev_slice * lanes + lane + 1) * segment_length - 1) * BLOCK_SIZE;//<bi> -- temporary variable for loading previous block
		for (uint8_t i = 0; i < 64; i++)
		{
			prev_block[i] = _mm_load_si128((__m128i *) &memory[bi]);
			bi += 16;
		}
	}

	next_block_offset = ((slice*lanes + lane)*segment_length + start)*BLOCK_SIZE;
	for(uint32_t i = start; i < segment_length; i++)
	{
		// compute block
		if ((i&ADDRESSES_MASK) == 0)
		{
			position_local.index = i / ADDRESSES_PER_BLOCK;
			GenerateAddresses(info, &position_local, addresses);
		}
		ComputeBlock(prev_block, memory+addresses[i&ADDRESSES_MASK], memory + next_block_offset);
		next_block_offset += BLOCK_SIZE;
	}
}



void FillMemory(const scheme_info_t* info)//Main loop: filling memory <t_cost> times
{
	vector<thread> Threads;
	position_info_t position(0,0,0,0);
	for (uint32_t p = 0; p < info->passes; p++)
	{
		position.pass = p;
		for (uint32_t s = 0; s < SYNC_POINTS; s++)
		{
			position.slice = s;
			for (uint32_t t = 0; t < info->lanes; t++)
			{
				position.lane = t;
				Threads.push_back(thread(FillSegment,info,position));
				//FillSegment(info, position);
			}
			for (auto& th : Threads)
			{
				th.join();
			}
			Threads.clear();
		}
#ifdef KAT_INTERNAL
		FILE* fp = fopen(KAT_FILENAME, "a+");
		fprintf(fp, "\n After pass %d:\n", p);
		for (uint32_t i = 0; i < info->mem_size; ++i)
		{
			fprintf(fp, "Block %.4d [0]: %x\n", i, *(uint32_t*)(info->state+i*BLOCK_SIZE));

		}
		fclose(fp);
#endif
	}
}


int Argon2iOpt(uint8_t *out, uint32_t outlen, const uint8_t *msg, uint32_t msglen, const uint8_t *nonce, uint32_t noncelen, const uint8_t *secret,
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
	if (m_cost < 2 * SYNC_POINTS*(uint32_t)lanes)
		m_cost = 2 * SYNC_POINTS*(uint32_t)lanes;
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

	
	//printf("---Begin---\n");
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
#ifdef KAT
	FILE* fp = fopen(KAT_FILENAME, "a+");

	fprintf(fp, "=======================================\n");
	fprintf(fp, "Iterations: %d, Memory: %d KBytes, Parallelism: %d lanes, Tag length: %d bytes\n", t_cost, m_cost, lanes, outlen);



	fprintf(fp, "Message: ");
	for (unsigned i = 0; i<msglen; ++i)
		fprintf(fp, "%2.2x ", ((unsigned char*)msg)[i]);
	fprintf(fp, "\n");
	fprintf(fp, "Nonce: ");
	for (unsigned i = 0; i<noncelen; ++i)
		fprintf(fp, "%2.2x ", ((unsigned char*)nonce)[i]);
	fprintf(fp, "\n");
	fprintf(fp, "Input Hash: ");
	for (unsigned i = 0; i<BLAKE_INPUT_HASH_SIZE; ++i)
		fprintf(fp, "%2.2x ", ((unsigned char*)blockhash)[i]);
	fprintf(fp, "\n");
	fclose(fp);
#endif

	allocate_memory(&memory,m_cost);
	scheme_info_t info(memory, m_cost, t_cost, lanes);
	
	Initialize(&info,blockhash); //Computing first two blocks in each segment


	FillMemory(&info);  //Filling memory with <t_cost> passes

	Finalize(memory, out,outlen, lanes, m_cost);

	free_memory(&memory);

#ifdef MEASURE
	end = __rdtscp(&ui2);
#endif
	//gettimeofday(&tv2, NULL);


	//print_block(&memory[(BLOCKS - 1) * BLOCK_SIZE]);
	
/*#ifdef MEASURE	
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
#endif*/

	return 0;
}

int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
	 unsigned int t_cost, unsigned int m_cost)
 {
	return Argon2iOpt((uint8_t*)out, (uint32_t)outlen, (const uint8_t*)in, (uint32_t)inlen, (const uint8_t*)salt, (uint32_t)saltlen, NULL, 0, NULL, 0, (uint32_t)t_cost, (uint32_t)m_cost, 1);
 }
