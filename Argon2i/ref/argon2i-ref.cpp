/*Argon2i Reference Implementation
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
#include "argon2i.h"




#define BLOCK(lane,slice,index) ((index)+(lane)*segment_length+(slice)*segment_length*(info->lanes))

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


void GenerateAddresses(const scheme_info_t* info, position_info_t* position, uint32_t* addresses)//generate 256 addresses 
{
	block zero_block, input_block, address_block;
	((uint32_t*)input_block.v)[0] = position->pass;
	((uint32_t*)input_block.v)[1] = position->lane;
	((uint32_t*)input_block.v)[2] = position->slice;
	((uint32_t*)input_block.v)[3] = position->index;
	((uint32_t*)input_block.v)[4] = 0xFFFFFFFF;
	MakeBlock(&zero_block, &input_block, &address_block);
	MakeBlock(&zero_block, &address_block, &address_block);
	uint8_t lanes = info->lanes;
	uint8_t slice = position->slice;
	uint8_t lane = position->lane;
	uint32_t pass = position->pass;

	/*Making block offsets*/
	uint32_t segment_length = info->mem_size / ((info->lanes)*SYNC_POINTS);
	uint32_t reference_area_size;//Number of blocks outside of the slice to reference
	/*Computing number of blocks to reference, except current slice*/
	if (position->pass == 0)
	{
		reference_area_size = lanes*slice*segment_length;
	}
	else
		reference_area_size = lanes*(SYNC_POINTS - 1)*segment_length;

	//Filling blocks, preparing macro for referencing blocks in memory

	uint32_t ref_index, ref_lane, ref_slice;
	for (uint32_t i = 0; i < ADDRESSES_PER_BLOCK; ++i)
	{
		if (position->slice == 0 && position->pass == 0 && position->index==0&& i <2)
			continue;
		uint32_t pseudo_rand = ((uint32_t*)address_block.v)[i];
		uint32_t total_area = reference_area_size  +(position->index)*ADDRESSES_PER_BLOCK+ i - 1;
		if (position->index == 0 && i == 0) //Special rule for the first block of the segment, except for the very beginning (i==0 is skipped in the first slice, first pass)
		{
			total_area -= lanes - 1; //Excluding last blocks of the other lanes
			uint32_t recalculation_start = 0;
			pseudo_rand %= total_area;
			if (slice == 0)
				recalculation_start = BLOCK(0, SYNC_POINTS - 2, 0);
			else
				recalculation_start = BLOCK(0, slice - 1, 0);
			if (pseudo_rand > recalculation_start)//we are in the previous slice and have to recalculate
			{
				uint32_t recalc_shift = (pseudo_rand - recalculation_start) / (segment_length - 1);
				pseudo_rand += (recalc_shift > lanes) ? (lanes) : recalc_shift; //Adding "missed" blocks to correctly locate reference block in the memory
			}
		}
		else
			pseudo_rand %= total_area;
		//Mapping pseudo_rand to the memory
		if (pseudo_rand >= reference_area_size)
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
		addresses[i] = BLOCK(ref_lane, ref_slice, ref_index);
	}
}


void FillSegment(const scheme_info_t* info, position_info_t* position)//Filling "slice" in "lane" and "round"
{
	uint32_t segment_length = info->mem_size /(info->lanes* (uint32_t)SYNC_POINTS);   //Computing length of the slice
	uint8_t lanes = info->lanes;
	uint8_t slice = position->slice;
	uint8_t lane = position->lane;
	uint32_t pass = position->pass;
	uint32_t addresses[ADDRESSES_PER_BLOCK];
	block prev_block;  //previous block
	
	for (uint32_t i = 0; i < segment_length; ++i)
	{
		/*0.Computing addresses if necessary*/
		if (i%ADDRESSES_PER_BLOCK == 0)
		{
			position->index = i / ADDRESSES_PER_BLOCK;
			GenerateAddresses(info, position, addresses);
		}
		/*1. First blocks*/
		if ((position->pass == 0) && (position->slice == 0) && (i < 2)) //skip first two blocks
			continue;

		/*2. Previous block*/
		uint32_t prev_index;
		if ((pass == 0) && (slice == 0) && (i == 2))
			prev_index = BLOCK(lane, 0, 1);
		if (i == 0)//not round 0, slice 0
		{
			if (slice == 0)
				prev_index = BLOCK(lane, SYNC_POINTS - 1, segment_length - 1);
			else
				prev_index = BLOCK(lane, slice - 1, segment_length - 1);
		}
		else prev_index = BLOCK(lane, slice, i - 1);
		prev_block = info->state[prev_index];
		
		/*2.Creating a new block*/
		block ref_block = info->state[addresses[i%ADDRESSES_PER_BLOCK]];  //pseudo-random block from memory
		
		block* next_block = &(info->state[BLOCK(position->lane, position->slice, i)]);
		MakeBlock(&prev_block, &ref_block, next_block);  //Create new block
		
	}

}

block*  Initialize(uint32_t outlen, const uint8_t *msg, uint32_t msglen, const uint8_t *nonce, uint32_t noncelen, const uint8_t *secret,
	uint8_t secretlen, const uint8_t *ad, uint32_t adlen, uint32_t t_cost, uint32_t m_cost, uint8_t lanes)
{

	//Initial hashing
	uint8_t blockhash[BLAKE_INPUT_HASH_SIZE+8];//H_0 in the document
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
		blake2b_long((uint8_t*)&(state[l*segment_length]),blockhash, BLOCK_SIZE, BLAKE_INPUT_HASH_SIZE + 8);
		blockhash[BLAKE_INPUT_HASH_SIZE] = 1;
		blake2b_long((uint8_t*)&(state[l*segment_length + 1]), blockhash, BLOCK_SIZE, BLAKE_INPUT_HASH_SIZE + 8);
	}
	memset(blockhash, 0, BLAKE_INPUT_HASH_SIZE + 8);
	return state;
}

void Finalize(scheme_info_t* info, uint8_t *out, uint32_t outlen)//XORing the last block of each lane, hashing it, making the tag.
{
	block blockhash;
	uint32_t segment_length = info->mem_size/ (info->lanes* (uint32_t)SYNC_POINTS);

	for (uint8_t l = 0; l < info->lanes; ++l)
	{
		blockhash = blockhash^ info->state[BLOCK(l, SYNC_POINTS - 1, segment_length - 1)];
	}
	blake2b_long(out, blockhash.v, outlen, BLOCK_SIZE);

	free_memory(info->state);

#ifdef KAT
	FILE* fp = fopen(KAT_FILENAME, "a+");
	fprintf(fp, "Tag: ");
	for (unsigned i = 0; i<outlen; ++i)
		fprintf(fp, "%2.2x ", ((uint8_t*)out)[i]);
	fprintf(fp, "\n");
	fclose(fp);
#endif 
	memset(blockhash.v, 0, BLOCK_SIZE);

	
}

void FillMemory(scheme_info_t* info) //Main loop: filling memory <t_cost> times
{
	for (uint32_t r = 0; r < info->passes; ++r)
	{
		for (uint8_t s = 0; s < SYNC_POINTS; ++s)
		{
			for (uint8_t l = 0; l < info->lanes; ++l)
			{
				position_info_t position(r, s, l);
				FillSegment(info,&position);
			}
		}
#ifdef KAT_INTERNAL
		FILE* fp = fopen(KAT_FILENAME, "a+");
		fprintf(fp, "\n After pass %d:\n", r);
		for (uint32_t i = 0; i < info->mem_size; ++i)
		{
			fprintf(fp, "Block %.4d [0]: %x\n", i, (uint32_t)info->state[i][0]);

		}
		fclose(fp);
#endif
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

	if (lanes>m_cost / BLOCK_SIZE_KILOBYTE)
		lanes = m_cost / BLOCK_SIZE_KILOBYTE;
	if (lanes<MIN_LANES)
		lanes = MIN_LANES;
	

	//printf("Argon2d called, %d m_cost %d lanes\n", m_cost, lanes);


	/*1. Initialization: Hashing inputs, allocating memory, filling first blocks*/
	block* state = Initialize( outlen, msg, msglen, nonce, noncelen, secret, secretlen, ad, adlen, t_cost, m_cost, lanes);//

	scheme_info_t info(state, m_cost, t_cost, lanes);
	/*2. Filling memory */
	FillMemory(&info);
	

	/*3. Finalization*/
	Finalize(&info, out, outlen);
	return 0;
}

int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
	 unsigned int t_cost, unsigned int m_cost)
 {
	return Argon2iRef((uint8_t*)out, (uint32_t)outlen, (const uint8_t*)in, (uint32_t)inlen, (const uint8_t*)salt, (uint32_t)saltlen, NULL, 0, NULL, 0, (uint32_t)t_cost, (uint32_t)m_cost, 1);
 }
