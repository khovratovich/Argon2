/*Argon2 Reference Implementation
  Code written by Dmitry Khovratovich in 2015.
  khovratovich@gmail.com*/



#include <stdio.h>


#include <stdint.h>
#include <time.h> 

#include <string.h>
#include <vector>
#include <thread>
using namespace std;

#include "blake-round.h"
#include "blake2-impl.h"
#include "blake2.h"
#include "argon2d.h"




#define BLOCK(lane,slice,index) ((index)+(lane)*segment_length+(slice)*segment_length*lanes)

void allocate_memory(block **memory, uint32_t m_cost)
{
	*memory = new block[m_cost];
	if (!*memory)
	{
		printf("Could not allocate the requested memory!\n");
		exit(1);
	}
}

void free_memory(block *memory)
{
	if (memory)
	{
		delete[] memory;
	}
}


void MakeBlock(block* prev_block, block* ref_block, block* next_block)
{
	block blockR = *prev_block ^ *ref_block;
	block blocktmp = blockR;
	
	// BLAKE2 - begin
	for (unsigned i = 0; i < 8; ++i)//Applying Blake2 on columns of 64-bit words: (0,1,...,15) , then (16,17,..31)... finally (112,113,...127)
	{

		BLAKE2_ROUND_NOMSG(blockR[16 * i], blockR[16 * i + 1], blockR[16 * i + 2], blockR[16 * i + 3], blockR[16 * i + 4],
			blockR[16 * i + 5], blockR[16 * i + 6], blockR[16 * i + 7], blockR[16 * i + 8], blockR[16 * i + 9], blockR[16 * i + 10],
			blockR[16 * i + 11], blockR[16 * i + 12], blockR[16 * i + 13], blockR[16 * i + 14], blockR[16 * i + 15]);
	}
	for (unsigned i = 0; i < 8; i++) //(0,1,16,17,...112,113), then (2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127)
	{
		BLAKE2_ROUND_NOMSG(blockR[2*i], blockR[2*i + 1], blockR[2*i + 16], blockR[2*i + 17], blockR[2*i + 32], blockR[2*i + 33], blockR[2*i + 48],
			blockR[2*i + 49], blockR[2*i + 64], blockR[2*i + 65], blockR[2*i + 80], blockR[2*i + 81], blockR[2*i + 96], blockR[2*i + 97],
			blockR[2*i + 112], blockR[2*i + 113]);
	}// BLAKE2 - end


	*next_block = blockR ^ blocktmp;
}





void FillSegment(block* state, uint32_t m_cost, uint8_t lanes, uint32_t round, uint8_t lane, uint8_t slice)//Filling "slice" in "lane" and "round"
{
	uint32_t segment_length = m_cost /(lanes* (uint32_t)SYNC_POINTS);   //Computing length of the slice

	uint32_t reference_area_size;//Number of blocks outside of the slice to reference
	/*Computing number of blocks to reference, except current slice*/
	if (round == 0)
	{
		reference_area_size = lanes*slice*segment_length;
	}
	else
		reference_area_size = lanes*(SYNC_POINTS-1)*segment_length;
	
	//Filling blocks, preparing macro for referencing blocks in memory

	uint32_t pseudo_rand, ref_index, ref_lane, ref_slice;
	block addresses;
	block prev_block;  //previous block
	for (uint32_t i = 0; i < segment_length; ++i)
	{
		/*0.Computing addresses if necessary*/
		if ((round == 0) && (slice == 0) && (i < 2)) //skip first two blocks
			continue;

		/*Reading previous block*/
		uint32_t prev_index;
		uint32_t recalculation_start=0;
		if ((round == 0) && (slice == 0) && (i == 2))
			prev_index = BLOCK(lane, 0, 1);
		if (i == 0)//not round 0, slice 0
		{
			if (slice == 0)
			{
				recalculation_start = BLOCK(0, SYNC_POINTS - 2, 0);
				prev_index = BLOCK(lane, SYNC_POINTS - 1, segment_length - 1);
			}
			else
			{
				recalculation_start = BLOCK(0, slice - 1, 0);
				prev_index = BLOCK(lane, slice - 1, segment_length - 1);
			}
		}
		else prev_index = BLOCK(lane, slice, i - 1);
		prev_block = state[prev_index];

		/*1. Computing the reference block*/
		/*1.1 Taking pseudo-random value from the previous block */
		pseudo_rand = *(uint32_t*)prev_block.v;
		/*1.2 Computing reference block location*/
		uint32_t total_area = (i == 0) ? (reference_area_size - lanes) : (reference_area_size + i - 1); //Excluding previous blocks and other last segment blocks if necessary
		pseudo_rand %= total_area;
		if (i == 0)
		{
			if (pseudo_rand > recalculation_start)//we are in the previous slice and have to recalculate
			{
				uint32_t recalc_shift = (pseudo_rand - recalculation_start)/(segment_length-1);
				pseudo_rand += (recalc_shift > lanes) ? (lanes) : recalc_shift; //Adding "missed" blocks to correctly locate reference block in the memory
			}
		}
		/*if ((i == 0) && ((pseudo_rand >= prev_index) && (slice>0) ||
			(pseudo_rand + m_cost / SYNC_POINTS >= prev_index) && (slice==0)))//If previous block is in another segment
				pseudo_rand++;*/
		if (pseudo_rand>=reference_area_size)
		{
			ref_index = pseudo_rand - reference_area_size;
			ref_slice = slice;
			ref_lane = lane;
		}
		else //Reference block is in other slices, in all lanes
		{
			
		
			ref_slice = pseudo_rand / (lanes*segment_length);
			ref_lane = (pseudo_rand / segment_length) % lanes;
			ref_index = pseudo_rand%segment_length;
			if (ref_slice >= slice) //This means we refer to next lanes in a previous pass
				ref_slice++;
		}
		/*2.Creating a new block*/
		block ref_block = state[BLOCK(ref_lane,ref_slice,ref_index)];  //random block from memory
		
		block* next_block = &(state[BLOCK(lane, slice, i)]);
		//printf("Ref: %.2d Next:%.2d\n", (ref_block - state) / BYTES_IN_BLOCK, (next_block - state) / BYTES_IN_BLOCK);
		MakeBlock(&prev_block, &ref_block, next_block);  //Create new block
		
	}

}

block*  Initialize(uint32_t outlen, const uint8_t *msg, uint32_t msglen, const uint8_t *nonce, uint32_t noncelen, const uint8_t *secret,
	uint8_t secretlen, const uint8_t *ad, uint32_t adlen, uint32_t t_cost, uint32_t m_cost, uint8_t lanes)
{

	//Initial hashing
	uint8_t blockhash[BLAKE_INPUT_HASH_SIZE + 8];//H_0 in the document
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


	blake2b_final(&BlakeHash, blockhash, BLAKE_INPUT_HASH_SIZE);
	memset(blockhash + BLAKE_INPUT_HASH_SIZE, 0, 8);

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

	//Memory allocation
	block* state;
	allocate_memory(&state, m_cost);

	//Creating first blocks, we always have at least two blocks in a slice

	uint32_t segment_length = m_cost / (lanes* (uint32_t)SYNC_POINTS);
	for (uint8_t l = 0; l < lanes; ++l)
	{
		blockhash[BLAKE_INPUT_HASH_SIZE + 4] = l;
		blockhash[BLAKE_INPUT_HASH_SIZE] = 0;
		blake2b_long((uint8_t*)&(state[l*segment_length]), blockhash, BLOCK_SIZE, BLAKE_INPUT_HASH_SIZE + 8);
		blockhash[BLAKE_INPUT_HASH_SIZE] = 1;
		blake2b_long((uint8_t*)&(state[l*segment_length + 1]), blockhash, BLOCK_SIZE, BLAKE_INPUT_HASH_SIZE + 8);
	}
	memset(blockhash, 0, BLAKE_INPUT_HASH_SIZE + 8);
	return state;
}

void Finalize(block* state, uint8_t *out, uint32_t outlen, uint32_t m_cost, uint8_t lanes)//XORing the last block of each lane, hashing it, making the tag.
{
	block blockhash;
	uint32_t segment_length = m_cost / (lanes* (uint32_t)SYNC_POINTS);

	for (uint8_t l = 0; l < lanes; ++l)
	{
		blockhash = blockhash^ state[BLOCK(l, SYNC_POINTS - 1, segment_length - 1)];
	}

	blake2b_long(out, blockhash.v, outlen, BLOCK_SIZE);

	free_memory(state);

#ifdef KAT
	FILE* fp = fopen(KAT_FILENAME, "a+");
	fprintf(fp, "Tag: ");
	for (unsigned i = 0; i<outlen; ++i)
		fprintf(fp, "%2.2x ", ((uint8_t*)out)[i]);
	fprintf(fp, "\n");
	fclose(fp);
#endif 
	memset(blockhash.v, 0, 64 * 16);

	
}

void FillMemory(block* state, uint32_t t_cost, uint32_t m_cost, uint8_t lanes) //Main loop: filling memory <t_cost> times
{
	for (uint8_t r = 0; r < t_cost; ++r)
	{
		for (uint8_t s = 0; s < SYNC_POINTS; ++s)
		{
			for (uint8_t l = 0; l < lanes; ++l)
			{
				FillSegment(state, m_cost, lanes, r, l, s);
			}
		}
#ifdef KAT_INTERNAL
		FILE* fp = fopen(KAT_FILENAME, "a+");
		fprintf(fp, "\n After pass %d:\n", r);
		for (uint32_t i = 0; i < m_cost; ++i)
		{
			fprintf(fp, "Block %.4d [0]: %x\n", i, state[i][0]);

		}
		fclose(fp);
#endif
	}
}

int Argon2dRef(uint8_t *out, uint32_t outlen, const uint8_t *msg, uint32_t msglen, const uint8_t *nonce, uint32_t noncelen, const uint8_t *secret,
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
		m_cost=2 * SYNC_POINTS*lanes;
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

	//printf("Argon2d called, %d m_cost %d lanes\n", m_cost, lanes);


	/*1. Initialization: Hashing inputs, allocating memory, filling first blocks*/
	block* state = Initialize( outlen, msg, msglen, nonce, noncelen, secret, secretlen, ad, adlen, t_cost, m_cost, lanes);//

	/*2. Filling memory */
	FillMemory(state, t_cost, m_cost, lanes);
	

	/*3. Finalization*/
	Finalize(state,out,outlen,m_cost,lanes);
	return 0;
}
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
	return Argon2dRef((uint8_t*)out, (uint32_t)outlen, (const uint8_t*)in, (uint32_t)inlen, (const uint8_t*)salt, (uint32_t)saltlen, NULL, 0, NULL, 0, (uint32_t)t_cost, (uint32_t)m_cost, 1);
}
