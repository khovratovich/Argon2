/*Argon2 Reference Implementation
  Code written by Dmitry Khovratovich in 2015.
  khovratovich@gmail.com*/



#include <stdio.h>


#include <stdint.h>
#include <time.h> 

#include <string>
#include <vector>
#include <thread>
using namespace std;

#include "blake-round.h"
#include "blake2-impl.h"
#include "blake2.h"
#include "argon2i.h"



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
	for (unsigned i = 0; i < 8; ++i)//Applying Blake2 on columns
	{

		BLAKE2_ROUND_NOMSG(blockR[16 * i], blockR[16 * i + 1], blockR[16 * i + 2], blockR[16 * i + 3], blockR[16 * i + 4],
			blockR[16 * i + 5], blockR[16 * i + 6], blockR[16 * i + 7], blockR[16 * i + 8], blockR[16 * i + 9], blockR[16 * i + 10],
			blockR[16 * i + 11], blockR[16 * i + 12], blockR[16 * i + 13], blockR[16 * i + 14], blockR[16 * i + 15]);
	}
	for (unsigned i = 0; i < 8; ++i)
	{
		BLAKE2_ROUND_NOMSG(blockR[i], blockR[i + 8], blockR[i + 16], blockR[i + 24], blockR[i + 32], blockR[i + 40], blockR[i + 48],
			blockR[i + 56], blockR[i + 64], blockR[i + 72], blockR[i + 80], blockR[i + 88], blockR[i + 96], blockR[i + 104],
			blockR[i + 112], blockR[i + 120]);
	}// BLAKE2 - end


	*next_block = blockR ^ blocktmp;
}

void GenerateAddresses(uint32_t round, uint8_t lane, uint8_t slice, uint32_t i, block* addresses)
{
	block zero_block,input_block;
	uint32_t input[4];
	input[0] = round;
	input[1] = lane;
	input[2] = slice;
	input[3] = i;
	memcpy(input_block.v, input, 4 * sizeof(uint32_t));
	MakeBlock(&zero_block, &input_block, addresses);
	MakeBlock(&zero_block, &addresses, addresses);
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
#define BLOCK(l,s,i) ((i)+(s)*segment_length+(l)*segment_length*SYNC_POINTS)

	uint32_t pseudo_rand, ref_index, ref_lane, ref_slice;
	block addresses;
	block prev_block;  //previous block
	for (uint32_t i = 0; i < segment_length; ++i)
	{
		/*0.Computing addresses if necessary*/
		if (i % ADDRESSES_IN_BLOCK == 0)
			GenerateAddresses(round, lane, slice, i / ADDRESSES_IN_BLOCK, &addresses);

		if ((round == 0) && (slice == 0) && (i < 2)) //skip first two blocks
			continue;
		
		/*Reading previous block*/
		uint32_t prev_index;
		if ((round == 0) && (slice == 0) && (i == 2))
			prev_index = BLOCK(lane, 0, 1);
		if (i == 0)//not round 0, slice 0
		{
			if (slice == 0)
				prev_index = BLOCK(lane, SYNC_POINTS - 1, segment_length - 1);
			else prev_index =BLOCK(lane, slice - 1, segment_length - 1);
		}
		else prev_index = BLOCK(lane, slice, i - 1);
		prev_block = state[prev_index];
		/*1. Computing the reference block*/
		/*1.1 Taking pseudo-random value from the list */
		pseudo_rand = ((uint32_t*)addresses.v)[i&0xff];
		/*1.2 Computing reference block location*/
		pseudo_rand %= (reference_area_size + i-1);//Previous block is excluded
		if ((i == 0) && ((pseudo_rand >= prev_index) && (slice>0) || (pseudo_rand + m_cost / SYNC_POINTS >= prev_index) && (slice==0)))//If previous block is in another segment
			pseudo_rand++;
		if (pseudo_rand>=reference_area_size)
		{
			ref_index = pseudo_rand - reference_area_size;
			ref_slice = slice;
			ref_lane = lane;
		}
		else //Reference block is in other slices, in all lanes
		{
			/*Number of available slices per lane is different for r==0 and others*/
			uint32_t available_slices = (round == 0) ? slice : (SYNC_POINTS - 1);

			ref_lane = pseudo_rand / (available_slices*segment_length);
			ref_index = pseudo_rand%segment_length;
			ref_slice = (pseudo_rand / segment_length) % available_slices;
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


int Argon2iRef(uint8_t *out, uint32_t outlen, const uint8_t *msg, uint32_t msglen, const uint8_t *nonce, uint32_t noncelen, const uint8_t *secret,
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

#ifdef KAT
	FILE* fp = fopen("kat-argon2i.log", "a+");

	fprintf(fp, "=======================================\n");
	fprintf(fp, "Iterations: %d, Memory: %d KBytes, Parallelism: %d lanes, Tag length: %d bytes\n", t_cost, m_cost, lanes, outlen);


#ifdef KAT
	fprintf(fp, "Message: ");
	for (unsigned i = 0; i<msglen; ++i)
		fprintf(fp, "%2.2x ", ((unsigned char*)msg)[i]);
	fprintf(fp, "\n");
	fprintf(fp, "Nonce: ");
	for (unsigned i = 0; i<noncelen; ++i)
		fprintf(fp, "%2.2x ", ((unsigned char*)nonce)[i]);
	fprintf(fp, "\n");

#endif

#endif

	//Initial hashing
	block blockhash;//H_0 in the document
	uint8_t version = VERSION_NUMBER;
	blake2b_state BlakeHash;
	blake2b_init(&BlakeHash, 32);

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
	

	blake2b_final(&BlakeHash, blockhash.v, 32);

	//Memory allocation
	block* state;  
	allocate_memory(&state, m_cost);

	/***Memory fill*/
	//Creating first blocks, we always have at least two blocks in a slice
	block blockcounter;
	uint32_t segment_length = m_cost / (lanes* (uint32_t)SYNC_POINTS);
	for (uint8_t l = 0; l < lanes; ++l)
	{
		blockcounter.v[4] = l;
		blockcounter.v[0] = 0;
		MakeBlock(&blockhash,&blockcounter, &(state[BLOCK(l,0,0)]));
		blockcounter.v[0] = 1;
		MakeBlock(&blockhash, &blockcounter, &(state[BLOCK(l, 0, 1)]));
	}
	memset(blockhash.v, 0, 64 * sizeof(__m128i));
	//Creating other blocks
	for (uint8_t r = 0; r < t_cost; ++r)
	{
		for (uint8_t s = 0; s < SYNC_POINTS; ++s)
		{
			for (uint8_t l = 0; l < lanes; ++l)
			{
				FillSegment(state,  m_cost, lanes, r,l,s);
			}
		}
	}
	

	/*3. Finalization*/
	for (uint8_t l = 0; l < lanes; ++l)
	{
		blockhash = blockhash^ state[BLOCK(l,SYNC_POINTS-1,segment_length-1)];
	}

	uint8_t tag_buffer[64];

	blake2b_init(&BlakeHash, 64);
	blake2b_update(&BlakeHash, (const uint8_t*)&blockhash, BYTES_IN_BLOCK);

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

	free_memory(state);

#ifdef KAT
	fprintf(fp, "Tag: ");
	for (unsigned i = 0; i<outlen; ++i)
		fprintf(fp, "%2.2x ", ((uint8_t*)out)[i]);
	fprintf(fp, "\n");
	fclose(fp);
#endif 

	return 0;
}

int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, uint32_t  saltlen,
	uint32_t t_cost, uint32_t m_cost)
{
	return Argon2iRef((uint8_t*)out, outlen, (const uint8_t*)in, inlen, (const uint8_t*)salt, saltlen, NULL, 0, NULL, 0, t_cost, m_cost, 1);
}
