/*
 * Argon2 source code package
 *
 * Written by Daniel Dinu and Dmitry Khovratovich, 2015
 *  
 * This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
 * 
 * You should have received a copy of the CC0 Public Domain Dedication along with
 * this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */


#include <stdint.h>


#include "argon2.h"
#include "argon2-core.h"
#include "kat.h"


#include "blamka-round-ref.h"
#include "blake2-impl.h"
#include "blake2.h"


const char* ARGON2_KAT_FILENAME = "kat-argon2-ref.log";


void FillBlock(const block* prev_block, const block* ref_block, block* next_block, const uint64_t* Sbox) {
    block blockR = *prev_block ^ *ref_block;
    block block_tmp = blockR;

    uint64_t x = 0;
    if (Sbox != NULL) {
        x = blockR[0] ^ blockR[ARGON2_WORDS_IN_BLOCK - 1];
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


    // Apply Blake2 on columns of 64-bit words: (0,1,...,15) , then (16,17,..31)... finally (112,113,...127)
    for (unsigned i = 0; i < 8; ++i) {
        BLAKE2_ROUND_NOMSG(blockR[16 * i], blockR[16 * i + 1], blockR[16 * i + 2], blockR[16 * i + 3],
                blockR[16 * i + 4], blockR[16 * i + 5], blockR[16 * i + 6], blockR[16 * i + 7],
                blockR[16 * i + 8], blockR[16 * i + 9], blockR[16 * i + 10], blockR[16 * i + 11],
                blockR[16 * i + 12], blockR[16 * i + 13], blockR[16 * i + 14], blockR[16 * i + 15]);
    }
    // Apply Blake2 on rows of 64-bit words: (0,1,16,17,...112,113), then (2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127)
    for (unsigned i = 0; i < 8; i++) {
        BLAKE2_ROUND_NOMSG(blockR[2 * i], blockR[2 * i + 1], blockR[2 * i + 16], blockR[2 * i + 17],
                blockR[2 * i + 32], blockR[2 * i + 33], blockR[2 * i + 48], blockR[2 * i + 49],
                blockR[2 * i + 64], blockR[2 * i + 65], blockR[2 * i + 80], blockR[2 * i + 81],
                blockR[2 * i + 96], blockR[2 * i + 97], blockR[2 * i + 112], blockR[2 * i + 113]);
    }

    *next_block = blockR ^ block_tmp;
    next_block->v[0] += x;
    next_block->v[ARGON2_WORDS_IN_BLOCK - 1] += x;
}

void GenerateAddresses(const Argon2_instance_t* instance, const Argon2_position_t* position, uint64_t* pseudo_rands) {
    block zero_block(0), input_block(0), address_block(0);
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
                FillBlock(&zero_block, &input_block, &address_block, NULL);
                FillBlock(&zero_block, &address_block, &address_block, NULL);
            }
            pseudo_rands[i] = address_block[i % ARGON2_ADDRESSES_IN_BLOCK];
        }
    }
}

void FillSegment(const Argon2_instance_t* instance, Argon2_position_t position) {
    if (instance == NULL) {
        return;
    }
    uint64_t pseudo_rand, ref_index, ref_lane;
    uint32_t prev_offset, curr_offset;
    bool data_independent_addressing = (instance->type == Argon2_i) || (instance->type == Argon2_id && (position.pass == 0) && (position.slice < ARGON2_SYNC_POINTS / 2));
    // Pseudo-random values that determine the reference block position
    uint64_t *pseudo_rands = new uint64_t[instance->segment_length];
    if (pseudo_rands == NULL){
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

    for (uint32_t i = starting_index; i < instance->segment_length; ++i, ++curr_offset, ++prev_offset) {
        /*1.1 Rotating prev_offset if needed */
        if (curr_offset % instance->lane_length == 1) {
            prev_offset = curr_offset - 1;
        }

        /* 1.2 Computing the index of the reference block */
        /* 1.2.1 Taking pseudo-random value from the previous block */
        if (data_independent_addressing) {
            pseudo_rand = pseudo_rands[i];
        } 
        else {
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
        FillBlock(instance->memory + prev_offset, ref_block, curr_block, instance->Sbox);
    }

    delete[] pseudo_rands;
}
    

void GenerateSbox(Argon2_instance_t* instance) {
    if (instance == NULL){
        return;
    }
    block zero_block(0), start_block(instance->memory[0]), out_block(0);
    
    if (instance->Sbox == NULL){
        instance->Sbox = new uint64_t[ARGON2_SBOX_SIZE];
    }
    for (uint32_t i = 0; i < ARGON2_SBOX_SIZE / ARGON2_WORDS_IN_BLOCK; ++i) {
        FillBlock(&zero_block, &start_block, &out_block, NULL);
        FillBlock(&zero_block, &out_block, &start_block, NULL);
        memcpy(instance->Sbox + i*ARGON2_WORDS_IN_BLOCK, start_block.v, ARGON2_BLOCK_SIZE);
    }
}
