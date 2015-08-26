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

#include "blake-round-mka.h"
#include "blake2-impl.h"
#include "blake2.h"
#include "argon2d.h"




#define BLOCK(lane,slice,index) ((index)+(lane)*segment_length+(slice)*segment_length*lanes)

/*
KAT function that prints the inputs to the file
*/
void InitialKat(uint8_t* blockhash, uint32_t outlen, const uint8_t *msg, uint32_t msglen, const uint8_t *nonce, uint32_t noncelen, const uint8_t *secret,
	uint8_t secretlen, const uint8_t *ad, uint32_t adlen, uint32_t t_cost, uint32_t m_cost, uint8_t lanes)
{
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
	for (unsigned i = 0; i<INPUT_INITIAL_HASH_LENGTH; ++i)
		fprintf(fp, "%2.2x ", ((unsigned char*)blockhash)[i]);
	fprintf(fp, "\n");
	fclose(fp);
}

/*
Function that prints the internal state
*/
void InternalKat(block* state, uint32_t m_cost, uint32_t pass)
{
	FILE* fp = fopen(KAT_FILENAME, "a+");
	fprintf(fp, "\n After pass %d:\n", pass);
	for (uint32_t i = 0; i < m_cost; ++i)
	{
		fprintf(fp, "Block %.4d [0]: %x\n", i, state[i][0]);

	}
	fclose(fp);
}

/*
Function that prints the output tag
*/
void PrintTag(void* out, uint32_t outlen)
{
	FILE* fp = fopen(KAT_FILENAME, "a+");
	fprintf(fp, "Tag: ");
	for (unsigned i = 0; i<outlen; ++i)
		fprintf(fp, "%2.2x ", ((uint8_t*)out)[i]);
	fprintf(fp, "\n");
	fclose(fp);
}

	

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

/*
*Function creates a new memory block*
**/

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


/****
*Function that fills the segment using previous segments also from other threads
****/
void FillSegment(block* state, uint32_t m_cost, uint8_t lanes, uint32_t round, uint8_t lane, uint8_t slice)//Filling "slice" in "lane" and "round"
{
	uint32_t segment_length = m_cost /(lanes* (uint32_t)SYNC_POINTS);   //Computing length of the slice

	uint32_t reference_area_size,start_position;//Number of blocks outside of the slice to reference
	
	uint32_t pseudo_rand, ref_index, ref_lane, ref_slice;
	block addresses;
	block prev_block;  //previous block
	for (uint32_t i = ((round == 0) && (slice == 0))?2:0; i < segment_length; ++i)
	{
		
		/*1.1. Computing the index of the previous block*/
		uint32_t prev_index;
		if ((round == 0) && (slice == 0) && (i == 2))
			prev_index = BLOCK(lane, 0, 1);
		else if (i == 0)//not round 0 & slice 0
		{
			if (slice == 0)
				prev_index = BLOCK(lane, SYNC_POINTS - 1, segment_length - 1);
			else
				prev_index = BLOCK(lane, slice - 1, segment_length - 1);
		}
		else prev_index = BLOCK(lane, slice, i - 1);
		prev_block = state[prev_index];

		/*1.2. Computing the index of the reference block*/
		/* 1.2.1 Taking pseudo-random value from the previous block */
		pseudo_rand = *(uint32_t*)prev_block.v;
		/*1.2.2 Computing the lane of the reference block*/
		ref_lane = (pseudo_rand >> 24) % lanes;

		/*1.2.3 Computing the number of possible reference block within the lane. 
		    Pass0:
			  This lane: all already finished segments plus already constructed blocks in this segment
			  Other lanes: all already finished segments
			Pass1+:
			  This lane:  (SYNC_POINTS-1) last segments plus already constructed blocks in this segment
			  Other lanes:  (SYNC_POINTS-1) last segments*/
		if (round == 0)//first pass
		{
			if (slice == 0)//first slice
			{
				ref_lane = lane;
				reference_area_size = i - 1; //all but the previous
			}
			else if (ref_lane == lane)//the same lane => add current segment
				reference_area_size = slice*segment_length + i - 1;
			else reference_area_size = slice*segment_length + ((i==0)?(- 1):0);
		}
		else //second pass, no first slice rule
		{
			if (ref_lane==lane)//the same lane
				reference_area_size = (SYNC_POINTS-1)*segment_length + i - 1;
			else reference_area_size = (SYNC_POINTS - 1)*segment_length + ((i == 0) ? (-1) : 0);
		}

		/*1.2.4. Mapping pseudo_rand to 0..<reference_area_size-2> and produce relative position*/
		uint64_t relative_position = (pseudo_rand & 0xFFFFFF); //last 24 bits for the position
		relative_position = relative_position*relative_position >> 24;
		relative_position = reference_area_size - 1 - ((reference_area_size - 1)*relative_position >> 24);

		/*1.2.5 Computing starting position*/
		if (round == 0)
			start_position = 0;
		else start_position = (slice == SYNC_POINTS - 1) ? 0 : (slice + 1)*segment_length;

		/*1.2.6. Computing absolute position*/
		uint64_t position = (start_position + relative_position) % (SYNC_POINTS*segment_length); //absolute position
		ref_index = position %segment_length;
		ref_slice = position / segment_length;

		/*2.Creating a new block*/
		block ref_block = state[BLOCK(ref_lane,ref_slice,ref_index)];  
		block* next_block = &(state[BLOCK(lane, slice, i)]);
		MakeBlock(&prev_block, &ref_block, next_block);  //Create new block
	}
}



/*
* Hashes all the inputs into blockhash[INPUT_INITIAL_HASH_LENGTH]
* TODO: make it endianness-independent
*/
void InitialHash(uint8_t* blockhash, uint32_t outlen, const uint8_t *msg, uint32_t msglen, const uint8_t *nonce, uint32_t noncelen, const uint8_t *secret,
	uint32_t secretlen, const uint8_t *ad, uint32_t adlen, uint32_t t_cost, uint32_t m_cost, uint8_t lanes)
{
	uint8_t version = VERSION_NUMBER;
	blake2b_state BlakeHash;
	blake2b_init(&BlakeHash, INPUT_INITIAL_HASH_LENGTH);

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


	blake2b_final(&BlakeHash, blockhash, INPUT_INITIAL_HASH_LENGTH);
}

/*
* Function creates first 2 blocks per lane
 */
void MakeFirstBlocks(uint8_t* blockhash, block* state, uint32_t m_cost, uint8_t lanes)
{
	uint32_t segment_length = m_cost / (lanes* (uint32_t)SYNC_POINTS);
	for (uint8_t l = 0; l < lanes; ++l)  //Make the first and second block in each lane as G(H0||i||0) or G(H0||i||1)
	{
		blockhash[INPUT_INITIAL_HASH_LENGTH + 4] = l;
		blockhash[INPUT_INITIAL_HASH_LENGTH] = 0;
		blake2b_long((uint8_t*)&(state[l*segment_length]), blockhash, BLOCK_SIZE, INPUT_INITIAL_HASH_LENGTH + 8);
		blockhash[INPUT_INITIAL_HASH_LENGTH] = 1;
		blake2b_long((uint8_t*)&(state[l*segment_length + 1]), blockhash, BLOCK_SIZE, INPUT_INITIAL_HASH_LENGTH + 8);
	}
}


/*
* Function hashes the inputs with Blake, allocates memory, and creates first two blocks. Returns the pointer to the main memory with 2 blocks per lane
* initialized
*/
block*  Initialize(uint32_t outlen, const uint8_t *msg, uint32_t msglen, const uint8_t *nonce, uint32_t noncelen, const uint8_t *secret,
	uint32_t secretlen, const uint8_t *ad, uint32_t adlen, uint32_t t_cost, uint32_t m_cost, uint8_t lanes)
{
	//1. Memory allocation
	block* state;
	allocate_memory(&state, m_cost);


	//2. Initial hashing  TODO - put in a separate function
	uint8_t blockhash[INPUT_INITIAL_HASH_LENGTH + 8];//H_0 +8 extra bytes to produce the first blocks
	InitialHash(blockhash, outlen, msg, msglen, nonce, noncelen, secret, secretlen, ad, adlen, t_cost, m_cost, lanes); //Hashing all inputs
	memset(blockhash + INPUT_INITIAL_HASH_LENGTH, 0, 8); //zeroing 8 extra bytes

#ifdef KAT
	InitialKat(blockhash, outlen, msg, msglen, nonce, noncelen, secret, secretlen, ad, adlen, t_cost, m_cost, lanes);
#endif

	//3. Creating first blocks, we always have at least two blocks in a slice
	MakeFirstBlocks(blockhash, state, m_cost, lanes);
	memset(blockhash, 0, INPUT_INITIAL_HASH_LENGTH + 8); //clearing the hash
	return state;
}

/*
* 
*XORing the last block of each lane, hashing it, making the tag.
*/
void Finalize(block* state, uint8_t *out, uint32_t outlen, uint32_t m_cost, uint8_t lanes)
{
	block blockhash;
	uint32_t segment_length = m_cost / (lanes* (uint32_t)SYNC_POINTS);

	//XOR the last blocks
	for (uint8_t l = 0; l < lanes; ++l)
	{
		blockhash = blockhash^ state[BLOCK(l, SYNC_POINTS - 1, segment_length - 1)];
	}

	blake2b_long(out, blockhash.v, outlen, BLOCK_SIZE);//Hash the XOR
	free_memory(state); //Deallocate the memory
#ifdef KAT
	PrintTag(out,outlen);
#endif 
	memset(blockhash.v, 0, 64 * 16);
}



/*
Function that fills the entire memory t_cost times based on the first two blocks in each lane
*/
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
		InternalKat(state,m_cost,r);
#endif
	}
}

/*
Function that validates all inputs against predefined restrictions and return an error code
*/
int ValidateInputs(uint8_t *out, uint32_t outlen, const uint8_t *msg, uint32_t msglen, const uint8_t *nonce, uint32_t noncelen, const uint8_t *secret,
	uint32_t secretlen, const uint8_t *ad, uint32_t adlen, uint32_t t_cost, uint32_t m_cost, uint8_t lanes)
{
	if (out == NULL)
		return NULL_OUTPUT_PTR;

	if (outlen > MAX_OUTLEN)
		return TOO_LONG_OUTPUT;
	if (outlen < MIN_OUTLEN)
		return TOO_SHORT_OUTPUT;  //Tag too short

	if (msglen > MAX_PWD_LENGTH)
		return TOO_LONG_PWD;
	if (msglen < MIN_PWD_LENGTH)
		return TOO_SHORT_PWD; //Password too short

	if (noncelen < MIN_SALT_LENGTH)
		return TOO_SHORT_SALT; //Salt too short
	if (noncelen > MAX_SALT_LENGTH)
		return TOO_LONG_SALT;

	if (secretlen > MAX_SECRET)
		return TOO_LONG_SECRET;
	if (secretlen < MIN_SECRET)
		return TOO_SHORT_SECRET; //Secret too short

	if (adlen > MAX_AD_LENGTH)
		return TOO_LONG_AD;
	if (adlen < MIN_AD_LENGTH)
		return TOO_SHORT_AD; //Associated data too short

	//minumum m_cost =8L blocks, where L is the number of lanes
	if (m_cost < 2 * SYNC_POINTS*lanes)
		m_cost = 2 * SYNC_POINTS*lanes;

	if (m_cost > MAX_MEMORY)
		return TOO_MUCH_MEMORY;

	m_cost = (m_cost / (lanes*SYNC_POINTS))*(lanes*SYNC_POINTS); //Ensure that all segments have equal length;

	if (t_cost < MIN_TIME)
		return TOO_SMALL_TIME;
	if (t_cost > MIN_TIME)
		return TOO_LARGE_TIME;

	if (lanes<MIN_LANES)
		return TOO_FEW_LANES;
	if (lanes > MAX_LANES)
		return TOO_MANY_LANES;
	return 0;
}

/*Function that performs memory-hard hashing with certain degree of parallelism*/
int Argon2d(uint8_t *out, uint32_t outlen, const uint8_t *msg, uint32_t msglen, const uint8_t *nonce, uint32_t noncelen, const uint8_t *secret,
	uint32_t secretlen, const uint8_t *ad, uint32_t adlen, uint32_t t_cost, uint32_t m_cost, uint8_t lanes)
{
	/*0. Validate all inputs*/
	int check_value = ValidateInputs(out, outlen, msg, msglen, nonce, noncelen, secret, secretlen, ad, adlen, t_cost, m_cost, lanes);
	if (check_value != 0)
		return check_value;
	
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
	return Argon2d((uint8_t*)out, (uint32_t)outlen, (const uint8_t*)in, (uint32_t)inlen, (const uint8_t*)salt, (uint32_t)saltlen, NULL, 0, NULL, 0, (uint32_t)t_cost, (uint32_t)m_cost, 1);
}
