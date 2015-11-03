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



#include <inttypes.h>
#include <vector>
#include <thread>
#include <cstring>

#include "argon2.h"
#include "argon2-core.h"
#include "kat.h"


#include "blake2.h"
#include "blake2-impl.h"


block operator^(const block& l, const block& r) {
    block a = l;
    a ^= r;
    return a;
}

int AllocateMemory(block **memory, uint32_t m_cost) {
    if (memory == NULL) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }
    try{
        *memory = new block[m_cost];
    }
    catch(std::bad_alloc& ba){
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }
    if (!*memory) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    return ARGON2_OK;
}


void ClearMemory(Argon2_instance_t* instance, bool clear) {
    if (instance->memory != NULL && clear) {
        if (instance->type == Argon2_ds && instance->Sbox != NULL) {
            secure_wipe_memory(instance->Sbox, ARGON2_SBOX_SIZE * sizeof (uint64_t));
        }
        secure_wipe_memory(instance->memory, sizeof (block) * instance->memory_blocks);
    }
}

void FreeMemory(block* memory) {
    delete[] memory;
    memory=nullptr;
}

void Finalize(const Argon2_Context *context, Argon2_instance_t* instance) {
    if (context != NULL && instance != NULL) {
        block blockhash = instance->memory[instance->lane_length - 1];

        // XOR the last blocks
        for (uint32_t l = 1; l < instance->lanes; ++l) {
            uint32_t last_block_in_lane = l * instance->lane_length + (instance->lane_length - 1);
            blockhash ^= instance->memory[last_block_in_lane];

        }

        // Hash the result
        blake2b_long(context->out,  context->outlen,(uint8_t*) blockhash.v, ARGON2_BLOCK_SIZE);
        secure_wipe_memory(blockhash.v, ARGON2_BLOCK_SIZE); //clear the blockhash

        if(context->print){ //Shall we print the output tag?
            PrintTag(context->out, context->outlen);
        }

        // Clear memory
        ClearMemory(instance, context->clear_memory);

        // Deallocate Sbox memory
        if (instance->memory != NULL && instance->Sbox != NULL) {
            delete[] instance->Sbox;
        }

        // Deallocate the memory
        if (NULL != context->free_cbk) {
            context->free_cbk((uint8_t *) instance->memory, instance->memory_blocks * sizeof (block));
        } else {
            FreeMemory(instance->memory);
        }

    }
}

uint32_t IndexAlpha(const Argon2_instance_t* instance, const Argon2_position_t* position, uint32_t pseudo_rand, bool same_lane) {
    /*
     * Pass 0:
     *      This lane : all already finished segments plus already constructed blocks in this segment
     *      Other lanes : all already finished segments
     * Pass 1+:
     *      This lane : (SYNC_POINTS - 1) last segments plus already constructed blocks in this segment
     *      Other lanes : (SYNC_POINTS - 1) last segments 
     */
    uint32_t reference_area_size;

    if (0 == position->pass) {
        // First pass
        if (0 == position->slice) {
            // First slice
            reference_area_size = position->index - 1; // all but the previous
        } else {
            if (same_lane) {
                // The same lane => add current segment
                reference_area_size = position->slice * instance->segment_length + position->index - 1;
            } else {
                reference_area_size = position->slice * instance->segment_length + ((position->index == 0) ? (-1) : 0);
            }
        }
    } else {
        // Second pass
        if (same_lane) {
            reference_area_size = instance->lane_length - instance->segment_length + position->index - 1;
        } else {
            reference_area_size = instance->lane_length - instance->segment_length + ((position->index == 0) ? (-1) : 0);
        }
    }

    /* 1.2.4. Mapping pseudo_rand to 0..<reference_area_size-1> and produce relative position */
    uint64_t relative_position = pseudo_rand;
    relative_position = relative_position * relative_position >> 32;
    relative_position = reference_area_size - 1 - (reference_area_size * relative_position >> 32);

    /* 1.2.5 Computing starting position */
    uint32_t start_position = 0;
    if (0 != position->pass) {
        start_position = (position->slice == ARGON2_SYNC_POINTS - 1) ? 0 : (position->slice + 1) * instance->segment_length;
    }

    /* 1.2.6. Computing absolute position */
    uint32_t absolute_position = (start_position + relative_position) % instance->lane_length; // absolute position
    return absolute_position;
}

void FillMemoryBlocks(Argon2_instance_t* instance) {
    std::vector<std::thread> Threads;
    if (instance == NULL) {
        return;
    }
    for (uint32_t r = 0; r < instance->passes; ++r) {
        if (Argon2_ds == instance->type) {
            GenerateSbox(instance);
        }
        for (uint8_t s = 0; s < ARGON2_SYNC_POINTS; ++s) {
            for (uint32_t l = 0; l < instance->lanes; ++l) {
                Threads.push_back(std::thread(FillSegment, instance, Argon2_position_t(r, l, s, 0)));
                if(instance->threads <= Threads.size()){ //have to join extra threads
                    for (auto& t : Threads) {
                        t.join();
                    }
                    Threads.clear();
                }
            }
            if(!Threads.empty()){
                for (auto& t : Threads) {
                    t.join();
                }
                Threads.clear();
            }
        }
        if(instance->internal_print){
            InternalKat(instance, r); // Print all memory blocks
        }
    }
}

int ValidateInputs(const Argon2_Context* context) {
    if (NULL == context) {
        return ARGON2_INCORRECT_PARAMETER;
    }

    if (NULL == context->out) {
        return ARGON2_OUTPUT_PTR_NULL;
    }

    /* Validate output length */
    if (ARGON2_MIN_OUTLEN > context->outlen) {
        return ARGON2_OUTPUT_TOO_SHORT;
    }
    if (ARGON2_MAX_OUTLEN < context->outlen) {
        return ARGON2_OUTPUT_TOO_LONG;
    }

    /* Validate password length */
    if (NULL == context->pwd) {
        if (0 != context->pwdlen) {
            return ARGON2_PWD_PTR_MISMATCH;
        }
    } else {
        if (ARGON2_MIN_PWD_LENGTH != 0 && ARGON2_MIN_PWD_LENGTH > context->pwdlen) {
            return ARGON2_PWD_TOO_SHORT;
        }
        if (ARGON2_MAX_PWD_LENGTH < context->pwdlen) {
            return ARGON2_PWD_TOO_LONG;
        }
    }

    /* Validate salt length */
    if (NULL == context->salt) {
        if (0 != context->saltlen) {
            return ARGON2_SALT_PTR_MISMATCH;
        }
    } else {
        if (ARGON2_MIN_SALT_LENGTH > context->saltlen) {
            return ARGON2_SALT_TOO_SHORT;
        }
        if (ARGON2_MAX_SALT_LENGTH < context->saltlen) {
            return ARGON2_SALT_TOO_LONG;
        }
    }

    /* Validate secret length */
    if (NULL == context->secret) {
        if (0 != context->secretlen) {
            return ARGON2_SECRET_PTR_MISMATCH;
        }
    } else {
        if (ARGON2_MIN_SECRET > context->secretlen) {
            return ARGON2_SECRET_TOO_SHORT;
        }
        if (ARGON2_MAX_SECRET < context->secretlen) {
            return ARGON2_SECRET_TOO_LONG;
        }
    }

    /* Validate associated data */
    if (NULL == context->ad) {
        if (0 != context->adlen) {
            return ARGON2_AD_PTR_MISMATCH;
        }
    } else {
        if (ARGON2_MIN_AD_LENGTH > context->adlen) {
            return ARGON2_AD_TOO_SHORT;
        }
        if (ARGON2_MAX_AD_LENGTH < context->adlen) {
            return ARGON2_AD_TOO_LONG;
        }
    }

    /* Validate memory cost */
    if (ARGON2_MIN_MEMORY > context->m_cost) {
        return ARGON2_MEMORY_TOO_LITTLE;
    }
    if (ARGON2_MAX_MEMORY < context->m_cost) {
        return ARGON2_MEMORY_TOO_MUCH;
    }

    /* Validate time cost */
    if (ARGON2_MIN_TIME > context->t_cost) {
        return ARGON2_TIME_TOO_SMALL;
    }
    if (ARGON2_MAX_TIME < context->t_cost) {
        return ARGON2_TIME_TOO_LARGE;
    }

    /* Validate lanes */
    if (ARGON2_MIN_LANES > context->lanes) {
        return ARGON2_LANES_TOO_FEW;
    }
    if (ARGON2_MAX_LANES < context->lanes) {
        return ARGON2_LANES_TOO_MANY;
    }
    
    /* Validate threads */
    if (ARGON2_MIN_THREADS > context->threads) {
        return ARGON2_THREADS_TOO_FEW;
    }
    if (ARGON2_MAX_THREADS < context->threads) {
        return ARGON2_THREADS_TOO_MANY;
    }

    if (NULL != context->allocate_cbk && NULL == context->free_cbk) {
        return ARGON2_FREE_MEMORY_CBK_NULL;
    }

    if (NULL == context->allocate_cbk && NULL != context->free_cbk) {
        return ARGON2_ALLOCATE_MEMORY_CBK_NULL;
    }

    return ARGON2_OK;
}

void FillFirstBlocks(uint8_t* blockhash, const Argon2_instance_t* instance) {
    // Make the first and second block in each lane as G(H0||i||0) or G(H0||i||1)
    for (uint32_t l = 0; l < instance->lanes; ++l) {
        store32(blockhash+ARGON2_PREHASH_DIGEST_LENGTH + 4,l);
        store32(blockhash+ARGON2_PREHASH_DIGEST_LENGTH,0);
        blake2b_long((uint8_t*) (instance->memory[l * instance->lane_length].v),  ARGON2_BLOCK_SIZE,blockhash, ARGON2_PREHASH_SEED_LENGTH);

        store32(blockhash+ARGON2_PREHASH_DIGEST_LENGTH,1);
        blake2b_long((uint8_t*) (instance->memory[l * instance->lane_length + 1].v),  ARGON2_BLOCK_SIZE,blockhash, ARGON2_PREHASH_SEED_LENGTH);
    }
}

void InitialHash(uint8_t* blockhash, Argon2_Context* context, Argon2_type type) {
    blake2b_state BlakeHash;
    uint8_t value[sizeof (uint32_t)];

    if (NULL == context || NULL == blockhash) {
        return;
    }

    blake2b_init(&BlakeHash, ARGON2_PREHASH_DIGEST_LENGTH);

    store32(&value, context->lanes);
    blake2b_update(&BlakeHash, (const uint8_t*) &value, sizeof (value));

    store32(&value, context->outlen);
    blake2b_update(&BlakeHash, (const uint8_t*) &value, sizeof (value));

    store32(&value, context->m_cost);
    blake2b_update(&BlakeHash, (const uint8_t*) &value, sizeof (value));

    store32(&value, context->t_cost);
    blake2b_update(&BlakeHash, (const uint8_t*) &value, sizeof (value));

    store32(&value, ARGON2_VERSION_NUMBER);
    blake2b_update(&BlakeHash, (const uint8_t*) &value, sizeof (value));

    store32(&value, (uint32_t) type);
    blake2b_update(&BlakeHash, (const uint8_t*) &value, sizeof (value));

    store32(&value, context->pwdlen);
    blake2b_update(&BlakeHash, (const uint8_t*) &value, sizeof (value));
    if (context->pwd != NULL) {
        blake2b_update(&BlakeHash, (const uint8_t*) context->pwd, context->pwdlen);
        if (context->clear_password) {
            secure_wipe_memory(context->pwd, context->pwdlen);
            context->pwdlen = 0;
        }
    }

    store32(&value, context->saltlen);
    blake2b_update(&BlakeHash, (const uint8_t*) &value, sizeof (value));
    if (context->salt != NULL) {
        blake2b_update(&BlakeHash, (const uint8_t*) context->salt, context->saltlen);
    }

    store32(&value, context->secretlen);
    blake2b_update(&BlakeHash, (const uint8_t*) &value, sizeof (value));
    if (context->secret != NULL) {
        blake2b_update(&BlakeHash, (const uint8_t*) context->secret, context->secretlen);
        if (context->clear_secret) {
            secure_wipe_memory(context->secret, context->secretlen);
            context->secretlen = 0;
        }
    }

    store32(&value, context->adlen);
    blake2b_update(&BlakeHash, (const uint8_t*) &value, sizeof (value));
    if (context->ad != NULL) {
        blake2b_update(&BlakeHash, (const uint8_t*) context->ad, context->adlen);
    }
    blake2b_final(&BlakeHash, blockhash, ARGON2_PREHASH_DIGEST_LENGTH);
}

int Initialize(Argon2_instance_t* instance, Argon2_Context* context) {
    if (instance == NULL || context == NULL)
        return ARGON2_INCORRECT_PARAMETER;
    
    // 1. Memory allocation
    int result = ARGON2_OK;
    if (NULL != context->allocate_cbk) {
         uint8_t *p;
        result = context->allocate_cbk(&p, instance->memory_blocks *
                                               ARGON2_BLOCK_SIZE);
        if (ARGON2_OK != result) {
            return result;
        }
        memcpy(&(instance->memory), p, sizeof(instance->memory));
    } else {
        result = AllocateMemory(&(instance->memory), instance->memory_blocks);
    }

    if (ARGON2_OK != result) {
        return result;
    }

    // 2. Initial hashing
    // H_0 + 8 extra bytes to produce the first blocks
    uint8_t blockhash[ARGON2_PREHASH_SEED_LENGTH];
    // Hashing all inputs
    InitialHash(blockhash, context, instance->type);
    // Zeroing 8 extra bytes
    secure_wipe_memory(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, ARGON2_PREHASH_SEED_LENGTH - ARGON2_PREHASH_DIGEST_LENGTH);

    if(context->print){ //shall we print the current state
        InitialKat(blockhash, context, instance->type);
    }

    // 3. Creating first blocks, we always have at least two blocks in a slice
    FillFirstBlocks(blockhash, instance);
    // Clearing the hash
    secure_wipe_memory(blockhash, ARGON2_PREHASH_SEED_LENGTH);

    return ARGON2_OK;
}

int Argon2Core(Argon2_Context* context, Argon2_type type) {
    /* 1. Validate all inputs */
    int result = ValidateInputs(context);
    if (ARGON2_OK != result) {
        return result;
    }
    if (Argon2_d != type && Argon2_i != type && Argon2_id != type && Argon2_ds != type) {
        return ARGON2_INCORRECT_TYPE;
    }

    /* 2. Align memory size */
    // Minimum memory_blocks = 8L blocks, where L is the number of lanes
    uint32_t memory_blocks = context->m_cost;
    if (memory_blocks < 2 * ARGON2_SYNC_POINTS * context->lanes) {
        memory_blocks = 2 * ARGON2_SYNC_POINTS * context->lanes;
    }
    uint32_t segment_length = memory_blocks / (context->lanes * ARGON2_SYNC_POINTS);
    // Ensure that all segments have equal length
    memory_blocks = segment_length * (context->lanes * ARGON2_SYNC_POINTS);
    const bool print_internals = context->print; //Should we print the memory blocks to the file
    Argon2_instance_t instance(NULL, type, context->t_cost, memory_blocks, context->lanes, context->threads,print_internals);

    /* 3. Initialization: Hashing inputs, allocating memory, filling first blocks */
    result = Initialize(&instance, context);
    if (ARGON2_OK != result) {
        return result;
    }

    /* 4. Filling memory */
    FillMemoryBlocks(&instance);

    /* 5. Finalization */
    Finalize(context, &instance);

    return ARGON2_OK;
}
