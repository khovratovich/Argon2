/*
 * Argon2 source code package
 * 
 *   
 * Written by Daniel Dinu and Dmitry Khovratovich, 2015
 * 
 * This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
 * 
 * You should have received a copy of the CC0 Public Domain Dedication along with
 * this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */


#include <stdint.h>


#if !defined(_MSC_VER)
#include <x86intrin.h>
#else
#include <emmintrin.h>
#include <smmintrin.h>
#include <intrin.h>
#endif


#include "argon2.h"
#include "argon2-core.h"
#include "kat.h"



#include "blake2.h"
#include "blamka-round-opt.h"



/* The KAT file name */
const char* ARGON2_KAT_FILENAME = "kat-argon2-opt.log";


//const __m128i r16 = _mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
//const __m128i r24 = _mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);

__m128i t0, t1;

/*
 * Function fills a new memory block
 * @param state Pointer to the just produced block. Content will be updated(!)
 * @param ref_block Pointer to the reference block
 * @param next_block Pointer to the block to be constructed
 * @param Sbox Pointer to the Sbox (used in Argon2_ds only)
 * @pre all block pointers must be valid
 */
void FillBlock(__m128i* state, const uint8_t *ref_block, uint8_t *next_block, const uint64_t* Sbox) {
    __m128i block_XY[ARGON2_QWORDS_IN_BLOCK];
    
     for (uint32_t i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {//Initial XOR
        block_XY[i] = state[i] = _mm_xor_si128(
            state[i], _mm_loadu_si128((__m128i const *)(&ref_block[16 * i])));
    }

    uint64_t x = 0;
    if (Sbox != NULL) { //S-boxes in Argon2ds
	x = *(uint64_t*)block_XY ^ ((uint64_t*)block_XY)[2 * ARGON2_QWORDS_IN_BLOCK - 1];
        for (int i = 0; i < 6 * 16; ++i) {
            uint32_t x1 = x >> 32;
            uint32_t x2 = x & 0xFFFFFFFF;
            uint64_t y = Sbox[x1 & ARGON2_SBOX_MASK];
            uint64_t z = Sbox[(x2 & ARGON2_SBOX_MASK) + ARGON2_SBOX_SIZE / 2];
            x = (uint64_t) x1 * (uint64_t) x2;
            x += y;
            x ^= z;
        }
    }

      for (uint32_t i = 0; i < 8; ++i) {
        BLAKE2_ROUND(state[8 * i + 0], state[8 * i + 1], state[8 * i + 2],
                     state[8 * i + 3], state[8 * i + 4], state[8 * i + 5],
                     state[8 * i + 6], state[8 * i + 7]);
    }

    for (uint32_t i = 0; i < 8; ++i) {
        BLAKE2_ROUND(state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i],
                     state[8 * 3 + i], state[8 * 4 + i], state[8 * 5 + i],
                     state[8 * 6 + i], state[8 * 7 + i]);
    }


    for (uint32_t i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
        // Feedback
        state[i] = _mm_xor_si128(state[i], block_XY[i]);
    }
    state[0] = _mm_add_epi64(state[0], _mm_set_epi64x(0, x));
    state[ARGON2_QWORDS_IN_BLOCK - 1] = _mm_add_epi64(state[ARGON2_QWORDS_IN_BLOCK - 1], _mm_set_epi64x(x, 0));
    for (uint32_t i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
                _mm_storeu_si128((__m128i *)(&next_block[16 * i]), state[i]);
    }
}

void GenerateAddresses(const Argon2_instance_t* instance, const Argon2_position_t* position, uint64_t* pseudo_rands) {
    block input_block(0), address_block(0);
    if (instance != NULL && position != NULL) {
        input_block.v[0] = position->pass;
        input_block.v[1] = position->lane;
        input_block.v[2] = position->slice;
        input_block.v[3] = instance->memory_blocks;
        input_block.v[4] = instance->passes;
        input_block.v[5] = instance->type;

        for (uint32_t i = 0; i < instance->segment_length; ++i) {
            if (i % ARGON2_ADDRESSES_IN_BLOCK == 0) {
                input_block.v[6]++;
                block zero_block(0), zero2_block(0);
                FillBlock((__m128i *) & zero_block.v, (uint8_t *) & input_block.v, (uint8_t *) & address_block.v, NULL);
                FillBlock((__m128i *) & zero2_block.v, (uint8_t *) & address_block.v, (uint8_t *) & address_block.v, NULL);
            }
            pseudo_rands[i] = address_block[i % ARGON2_ADDRESSES_IN_BLOCK];
        }
    }
}

/*
 * Function that fills the segment using previous segments also from other threads. Identical to the reference code except that it calls optimized FillBlock()
 * @param instance Pointer to the current instance
 * @param position Current position
 * @pre all block pointers must be valid
 */
void FillSegment(const Argon2_instance_t* instance, Argon2_position_t position) {
 	if (instance == NULL){
	   return;
 	}    
	uint64_t pseudo_rand, ref_index, ref_lane;
	uint32_t prev_offset, curr_offset;
	__m128i state[64];
	bool data_independent_addressing = (instance->type == Argon2_i) || (instance->type == Argon2_id && (position.pass == 0) && (position.slice < ARGON2_SYNC_POINTS / 2));

    
   // Pseudo-random values that determine the reference block position
   uint64_t *pseudo_rands = new uint64_t[instance->segment_length];
   if (pseudo_rands == NULL) {
		return;
	}
   if (data_independent_addressing) {
       GenerateAddresses(instance, &position, pseudo_rands);
   }

   uint32_t starting_index = 0;
   if ((0 == position.pass) && (0 == position.slice)) {
       starting_index = 2; // we have already generated the first two blocks
   }

   // Offset of the current block
   curr_offset = position.lane * instance->lane_length + position.slice * instance->segment_length + starting_index;
   if (0 == curr_offset % instance->lane_length) {
       // Last block in this lane
       prev_offset = curr_offset + instance->lane_length - 1;
   } else {
       // Previous block
       prev_offset = curr_offset - 1;
   }
   memcpy(state, (uint8_t *) ((instance->memory + prev_offset)->v), ARGON2_BLOCK_SIZE);
   for (uint32_t i = starting_index; i < instance->segment_length; ++i, ++curr_offset, ++prev_offset) {
       /*1.1 Rotating prev_offset if needed */
       if (curr_offset % instance->lane_length == 1) {
           prev_offset = curr_offset - 1;
       }

       /* 1.2 Computing the index of the reference block */
       /* 1.2.1 Taking pseudo-random value from the previous block */
       if (data_independent_addressing) {
           pseudo_rand = pseudo_rands[i];
       } else {
           pseudo_rand = instance->memory[prev_offset][0];
       }

       /* 1.2.2 Computing the lane of the reference block */
       ref_lane = ((pseudo_rand >> 32)) % instance->lanes;
       if ((position.pass == 0) && (position.slice == 0)) {
           // Can not reference other lanes yet
           ref_lane = position.lane;
       }

       /* 1.2.3 Computing the number of possible reference block within the lane. */
       position.index = i;
       ref_index = IndexAlpha(instance, &position, pseudo_rand & 0xFFFFFFFF, ref_lane == position.lane);

       /* 2 Creating a new block */
       block* ref_block = instance->memory + instance->lane_length * ref_lane + ref_index;
       block* curr_block = instance->memory + curr_offset;
       FillBlock(state, (uint8_t *) ref_block->v, (uint8_t *) curr_block->v, instance->Sbox);
   }

   delete[] pseudo_rands;
   
}

void GenerateSbox(Argon2_instance_t* instance) {
    if (instance == NULL) {
        return;
    }
    block start_block(instance->memory[0]), out_block(0), zero_block(0);
    
    if (instance->Sbox == NULL) {
        instance->Sbox = new uint64_t[ARGON2_SBOX_SIZE];
    }

    for (uint32_t i = 0; i < ARGON2_SBOX_SIZE / ARGON2_WORDS_IN_BLOCK; ++i) {
        block zero_block(0), zero2_block(0);
        FillBlock((__m128i*) zero_block.v, (uint8_t*) start_block.v, (uint8_t*) out_block.v, NULL);
        FillBlock((__m128i*) zero2_block.v, (uint8_t*) out_block.v, (uint8_t*) start_block.v, NULL);
        memcpy(instance->Sbox + i * ARGON2_WORDS_IN_BLOCK, start_block.v, ARGON2_BLOCK_SIZE);
    }
}
