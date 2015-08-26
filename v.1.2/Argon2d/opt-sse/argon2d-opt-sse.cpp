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
#include "blake2-round-mka.h"
#include "blake2.h"

// Constants
#include "argon2d.h"


// The block size in bytes
#ifndef BLOCK_SIZE
#define BLOCK_SIZE 1024
#endif


#define MEASURE

struct info {
	uint64_t pass;
	uint64_t slice;
	uint64_t lane;
};




__m128i t0, t1;
const __m128i r16 = _mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
const __m128i r24 = _mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);



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

	for(unsigned i=0; i<1; ++i)
{

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
		state[34], state[42], state[50], state[58])
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
}
	for (uint8_t i = 0; i< 64; i++)
	{
		state[i] = _mm_xor_si128(state[i], ref_block[i]); //Feedback
		_mm_store_si128((__m128i *) next_block_ptr, state[i]);
		next_block_ptr += 16;
	}
}



void Initialize(scheme_info_t* info, uint8_t* input_hash)
{
	uint8_t block_input[INPUT_INITIAL_HASH_LENGTH + 8];
	uint32_t segment_length = (info->mem_size / (SYNC_POINTS*(info->lanes)));
	memcpy(block_input, input_hash, INPUT_INITIAL_HASH_LENGTH);
	memset(block_input + INPUT_INITIAL_HASH_LENGTH, 0, 8);
	for (uint8_t l = 0; l < info->lanes; ++l)
	{
		block_input[INPUT_INITIAL_HASH_LENGTH + 4] = l;
		block_input[INPUT_INITIAL_HASH_LENGTH] = 0;
		blake2b_long(info->state + l * segment_length*BLOCK_SIZE, block_input, BLOCK_SIZE, INPUT_INITIAL_HASH_LENGTH + 8);
		block_input[INPUT_INITIAL_HASH_LENGTH] = 1;
		blake2b_long(info->state + (l * segment_length + 1)*BLOCK_SIZE, block_input, BLOCK_SIZE, INPUT_INITIAL_HASH_LENGTH + 8);
	}
	memset(block_input, 0, INPUT_INITIAL_HASH_LENGTH + 8);
}

void Finalize(scheme_info_t* info, uint8_t* out, uint32_t outlen)//XORing the last block of each lane, hashing it, making the tag.
{
	__m128i blockhash[BLOCK_SIZE / 16];
	memset(blockhash, 0, BLOCK_SIZE);
	for (uint8_t l = 0; l < info->lanes; ++l)//XORing all last blocks of the lanes
	{
		uint32_t segment_length = (info->mem_size) / (SYNC_POINTS*(info->lanes));
		uint8_t* block_ptr = info->state + (((SYNC_POINTS - 1)*(info->lanes) + l + 1)*segment_length - 1)*BLOCK_SIZE; //points to the last block of the first lane

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

void FillSegment(scheme_info_t *info, position_info_t pos)
{
	__m128i prev_block[64];

	uint32_t next_block_offset;
	uint8_t lanes = info->lanes;
	uint8_t* memory = info->state;
	uint32_t phi;
	uint32_t phi2;

	uint32_t segment_length = (info->mem_size) / (lanes*SYNC_POINTS);
	//uint32_t stop = segment_length;//Number of blocks to produce in the segment, is different for the first slice, first pass
	uint32_t start=0;

	uint32_t prev_block_offset; //offset of previous block
	uint32_t prev_block_recalc=0; //number of the first block in the reference area in the previous slice 

	if(0 == pos.pass && 0 == pos.slice) // First pass; first slice
	{
		start += 3;
		if (segment_length <= 2)
			return;

		uint32_t bi = prev_block_offset = (pos.lane * segment_length + 1) * BLOCK_SIZE;//<bi> -- temporary variable for loading previous block
		for (uint8_t i = 0; i < 64; i++)
		{
			prev_block[i] = _mm_load_si128((__m128i *) &memory[bi]);
			bi += 16;
		}
		
		next_block_offset = (pos.lane * segment_length + 2) * BLOCK_SIZE;

		uint32_t reference_block_offset = (pos.lane * segment_length) * BLOCK_SIZE;

		// compute block
		ComputeBlock(prev_block, memory+ reference_block_offset, memory+next_block_offset);//Computing third block in the segment

		phi = _mm_extract_epi32(prev_block[0], 0); 
	}
	else
	{
		uint32_t prev_slice = (pos.slice>0)?(pos.slice-1):(SYNC_POINTS-1);
		prev_block_recalc = (pos.slice > 0) ? ((pos.slice - 1)*lanes*segment_length) : (SYNC_POINTS - 2)*lanes*segment_length;
		uint32_t bi = prev_block_offset = ((prev_slice * lanes + pos.lane + 1) * segment_length - 1) * BLOCK_SIZE;//<bi> -- temporary variable for loading previous block
		for (uint8_t i = 0; i < 64; i++)
		{
			prev_block[i] = _mm_load_si128((__m128i *) &memory[bi]);
			bi += 16;
		}
		
		phi = _mm_extract_epi32(prev_block[0], 0);
	}

	next_block_offset = ((pos.slice*lanes + pos.lane)*segment_length + start)*BLOCK_SIZE;
	for(uint32_t i = start; i < segment_length; i++)
	{
		/*NEW*/
		uint8_t ref_lane;
		if(pos.pass==0 && pos.slice==0)
			ref_lane = pos.lane;
		else ref_lane = (phi>>24)%lanes; //lane to where we reference
		uint32_t ref_positions; //how many positions we can reference in that lane
		uint32_t start_position;
		
		if(ref_lane==pos.lane) //this lane
		{
			if(pos.pass==0)//first pass
				ref_positions = (pos.slice)*segment_length+i-1;
			else
				ref_positions = (SYNC_POINTS-1)*segment_length+i-1;
		}
		else
		{
			if(pos.pass==0)//first pass => not the first slice
				ref_positions = (pos.slice)*segment_length - ((i==0)?1:0);

			else ref_positions = (SYNC_POINTS-1)*segment_length - ((i==0)?1:0);
		}
		uint64_t position = (phi&0xFFFFFF);
		position = position*position >> 24;
		position = ref_positions-1-((ref_positions-1)*position >>24);
		
		//Computing offset
		if(pos.pass==0)
			start_position = 0;
		else start_position = (pos.slice+1)*segment_length;
		position = (start_position + position) % (SYNC_POINTS*segment_length); //absolute position
		uint32_t ref_slice = position / segment_length;
		uint32_t ref_index = position % segment_length;
		uint32_t reference_block_offset = (ref_index + (ref_lane + ref_slice*lanes) *segment_length)*BLOCK_SIZE;
		/*END-NEW*/
	
		// compute block
		ComputeBlock(prev_block, memory + reference_block_offset, memory+next_block_offset);
		phi = _mm_extract_epi32(prev_block[0], 0);
		next_block_offset += BLOCK_SIZE;
	}
}



void FillMemory(scheme_info_t *info)//Main loop: filling memory <t_cost> times
{
	vector<thread> Threads;
	vector<position_info_t> positions(info->lanes);
	for (uint32_t p = 0; p < info->passes; p++)
	{
		for (uint32_t s = 0; s < SYNC_POINTS; s++)
		{
			for (uint32_t t = 0; t < info->lanes; t++)
			{
				positions[t].pass = p;
				positions[t].slice = s;
				positions[t].lane = t;
				Threads.push_back(thread(FillSegment,info,positions[t]));
				//FillSegment(info,positions[t]);
		
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

/*Optimized version */
int Argon2d(uint8_t *out, uint32_t outlen, const uint8_t *msg, uint32_t msglen, const uint8_t *nonce, uint32_t noncelen, const uint8_t *secret,
	uint8_t secretlen, const uint8_t *ad, uint32_t adlen, uint32_t t_cost, uint32_t m_cost, uint8_t lanes)
{
	/*0. Validate all inputs*/
	int check_value = ValidateInputs(out, outlen, msg, msglen, nonce, noncelen, secret, secretlen, ad, adlen, t_cost, m_cost, lanes);
	if (check_value != 0)
		return check_value;

	unsigned int ui1, ui2; 
	uint8_t *memory;
	
#ifdef MEASURE
	uint64_t begin, end;
	begin = __rdtscp(&ui1);
#endif 

	//Initial hashing
	uint8_t blockhash[INPUT_INITIAL_HASH_LENGTH];//H_0 in the document
	InitialHash(blockhash, outlen, msg, msglen, nonce, noncelen, secret, secretlen, ad, adlen, t_cost, m_cost, lanes); //Hashing all inputs
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

	Finalize(&info, out,outlen);

	free_memory(&memory);

#ifdef MEASURE
	end = __rdtscp(&ui2);
#endif
	return 0;
}

int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
	return Argon2d((uint8_t*)out, (uint32_t)outlen, (const uint8_t*)in, (uint32_t)inlen, (const uint8_t*)salt, (uint32_t)saltlen, NULL, 0, NULL, 0, (uint32_t)t_cost, (uint32_t)m_cost, 1);
}
