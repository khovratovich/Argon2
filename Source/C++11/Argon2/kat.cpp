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



#include <cstdio>
#include <inttypes.h>

#include <string>

#include "argon2.h"
#include "argon2-core.h"
#include "kat.h"



void InitialKat(const uint8_t* blockhash, const Argon2_Context* context, Argon2_type type) {
    FILE* fp = fopen(ARGON2_KAT_FILENAME, "a+");

    if (fp && blockhash != NULL && context != NULL) {
        fprintf(fp, "=======================================");

        switch (type) {
            case Argon2_d:
                fprintf(fp, "Argon2d\n");
                break;
            case Argon2_i:
                fprintf(fp, "Argon2i\n");
                break;
            case Argon2_id:
                fprintf(fp, "Argon2id\n");
                break;
            case Argon2_ds:
                fprintf(fp, "Argon2ds\n");
                break;
	    default:
		break;
        }

        fprintf(fp, "Iterations: %u, Memory: %u KBytes, Parallelism: %u lanes, Tag length: %u bytes\n",
                context->t_cost, context->m_cost, context->lanes, context->outlen);


        fprintf(fp, "Password[%u]: ", context->pwdlen);
        if (context->clear_password) {
            fprintf(fp, "CLEARED\n");
        } else {
            for (unsigned i = 0; i < context->pwdlen; ++i) {
                fprintf(fp, "%2.2x ", ((unsigned char*) context->pwd)[i]);
            }
            fprintf(fp, "\n");
        }


        fprintf(fp, "Salt[%u]: ", context->saltlen);
        for (unsigned i = 0; i < context->saltlen; ++i) {
            fprintf(fp, "%2.2x ", ((unsigned char*) context->salt)[i]);
        }
        fprintf(fp, "\n");

        fprintf(fp, "Secret[%u]: ", context->secretlen);

        if (context->clear_secret) {
            fprintf(fp, "CLEARED\n");
        } else {
            for (unsigned i = 0; i < context->secretlen; ++i) {
                fprintf(fp, "%2.2x ", ((unsigned char*) context->secret)[i]);
            }
            fprintf(fp, "\n");
        }

        fprintf(fp, "Associated data[%u]: ", context->adlen);
        for (unsigned i = 0; i < context->adlen; ++i) {
            fprintf(fp, "%2.2x ", ((unsigned char*) context->ad)[i]);
        }
        fprintf(fp, "\n");



        fprintf(fp, "Pre-hashing digest: ");
        for (unsigned i = 0; i < ARGON2_PREHASH_DIGEST_LENGTH; ++i) {
            fprintf(fp, "%2.2x ", ((unsigned char*) blockhash)[i]);
        }
        fprintf(fp, "\n");

        fclose(fp);
    }
}

void PrintTag(const void* out, uint32_t outlen) {
    FILE* fp = fopen(ARGON2_KAT_FILENAME, "a+");

    if (fp && out != NULL) {
        fprintf(fp, "Tag: ");
        for (unsigned i = 0; i < outlen; ++i) {
            fprintf(fp, "%2.2x ", ((uint8_t*) out)[i]);
        }
        fprintf(fp, "\n");

        fclose(fp);
    }
}

void InternalKat(const Argon2_instance_t* instance, uint32_t pass) {
    FILE* fp = fopen(ARGON2_KAT_FILENAME, "a+");
    if (fp && instance != NULL) {
        fprintf(fp, "\n After pass %u:\n", pass);
        for (uint32_t i = 0; i < instance->memory_blocks; ++i) {
            uint32_t how_many_words = (instance->memory_blocks > ARGON2_WORDS_IN_BLOCK) ? 1 : ARGON2_WORDS_IN_BLOCK;
            for (uint32_t j = 0; j < how_many_words; ++j)
                fprintf(fp, "Block %.4d [%3u]: %016" PRIx64 "\n", i, j, instance->memory[i][j]);
        }

        fclose(fp);
    }
}

void Fatal(const char *error_msg) {
    if(nullptr!= error_msg){
        fprintf(stderr, "Error: %s\n", error_msg);
    }
    exit(1);
        
}

/*Generate test vectors of Argon2 of type @type
 * 
 */
void GenerateTestVectors(const std::string &type) {
    
    /*Fixed parameters for test vectors*/
    const unsigned out_length = 32;
    const unsigned pwd_length = 32;
    const unsigned salt_length = 16;
    const unsigned secret_length = 8;
    const unsigned ad_length = 12;
    const unsigned char password_symbol=1;
    const unsigned char salt_symbol=2;
    const unsigned char secret_symbol=3;
    const unsigned char ad_symbol=4;
    bool clear_memory = false;
    bool clear_secret = false;
    bool clear_password = false;
    const bool print_internals = true; //since we generate test vectors
    const AllocateMemoryCallback myown_allocator = NULL;
    const FreeMemoryCallback myown_deallocator = NULL;
    const uint32_t t_cost = 3;
    const uint32_t m_cost = 16;
    const uint32_t lanes = 4;
    const uint32_t threads = lanes;


     /*Temporary arrays*/
    uint8_t out[out_length];
    uint8_t pwd[pwd_length];
    uint8_t salt[salt_length];
    uint8_t secret[secret_length];
    uint8_t ad[ad_length];

    
    memset(pwd, password_symbol, pwd_length);
    memset(salt, salt_symbol, salt_length);
    memset(secret, secret_symbol, secret_length);
    memset(ad, ad_symbol, ad_length);

    printf("Generate test vectors in file: \"%s\".\n", ARGON2_KAT_FILENAME);

    Argon2_Context context(out, out_length, pwd, pwd_length, salt, salt_length,
            secret, secret_length, ad, ad_length, t_cost, m_cost, lanes, threads,
            myown_allocator, myown_deallocator,
            clear_password, clear_secret, clear_memory,print_internals);

    if (type == std::string("Argon2d")) {
        printf("Test Argon2d\n");
        Argon2d(&context);
        return;
    }
    else if (type == std::string("Argon2i")) {
        printf("Test Argon2i\n");
        Argon2i(&context);
        return;
    }
    else if (type == std::string("Argon2ds")) {
        printf("Test Argon2ds\n");
        Argon2ds(&context);
        return;
    }
    else if (type == std::string("Argon2id")) {
        printf("Test Argon2id\n");
        Argon2id(&context);
        return;
    }
    else{
        printf("Wrong Argon2 type!\n");
    }
}

