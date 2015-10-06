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


#include <stdio.h>
#include <stdint.h>
#include <random>
#include <cstring>
#include <algorithm>
#include <vector>
#include <string>

#include "time.h"
#include "argon2.h"


/* Enable timing measurements */
#define _MEASURE

/*Fixes the cycle count to @aux*/
static inline uint64_t rdtscp(uint32_t *aux) {
    uint64_t rax, rdx;
    asm volatile ( "rdtscp\n" : "=a" (rax), "=d" (rdx), "=c" (aux) : : );
    return (rdx << 32) + rax;
}

/*
 * Custom allocate memory to @memory of size @length
 */
int CustomAllocateMemory(uint8_t **memory, size_t length) {
    *memory = new uint8_t[length];
    if (!*memory) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }
    return ARGON2_OK;
}

/*
 * Custom free memory at @memory of size @length
 */
void CustomFreeMemory(uint8_t *memory, size_t length) {
    if (memory) {
        delete[] memory;
    }
}


/*
 * Benchmarks Argon2 with salt length 16, password length 32, t_cost 3, and different threads and m_cost
 */
void Benchmark() {
    const uint32_t inlen = 16;
    const unsigned outlen=16;
    unsigned char out[outlen];
    unsigned char pwd_array[inlen];
    unsigned char salt_array[inlen];

    uint32_t t_cost = 1;

    memset(pwd_array, 0, inlen);
    memset(salt_array, 1, inlen);
    std::vector<uint32_t> thread_test = {1, 2, 4, 6, 8, 16};

    for (uint32_t m_cost = (uint32_t) 1 << 10; m_cost <= (uint32_t) 1 << 22; m_cost *= 2) {
        for (uint32_t thread_n : thread_test) {

#ifdef _MEASURE
            uint64_t start_cycles, stop_cycles, stop_cycles_i, stop_cycles_di, stop_cycles_ds;
            uint32_t ui1, ui2, ui3, ui4, ui5;

            clock_t start_time = clock();
            start_cycles = rdtscp(&ui1);
#endif

            Argon2_Context context(out, outlen, pwd_array, inlen, salt_array, inlen, NULL, 0, NULL, 0, t_cost, m_cost, thread_n,NULL,NULL,false,false, false);
            Argon2d(&context);

#ifdef _MEASURE
            stop_cycles = rdtscp(&ui2);
#endif
            Argon2i(&context);
#ifdef _MEASURE
            stop_cycles_i = rdtscp(&ui3);
#endif
            Argon2id(&context);
#ifdef _MEASURE
            stop_cycles_di = rdtscp(&ui4);
#endif
            Argon2ds(&context);
#ifdef _MEASURE
            stop_cycles_ds = rdtscp(&ui5);
            clock_t stop_time = clock();

            uint64_t delta_d = (stop_cycles - start_cycles) / (m_cost);
            uint64_t delta_i = (stop_cycles_i - stop_cycles) / (m_cost);
            uint64_t delta_id = (stop_cycles_di - stop_cycles_i) / m_cost;
            uint64_t delta_ds = (stop_cycles_ds - stop_cycles_di) / m_cost;
            float mcycles_d = (float) (stop_cycles - start_cycles) / (1 << 20);
            float mcycles_i = (float) (stop_cycles_i - stop_cycles) / (1 << 20);
            float mcycles_id = (float) (stop_cycles_di - stop_cycles_i) / (1 << 20);
            float mcycles_ds = (float) (stop_cycles_ds - stop_cycles_di) / (1 << 20);
            printf("Argon2d %d pass(es)  %d Mbytes %d threads:  %2.2f cpb %2.2f Mcycles \n", t_cost, m_cost >> 10, thread_n, (float) delta_d / 1024, mcycles_d);
            printf("Argon2i %d pass(es)  %d Mbytes %d threads:  %2.2f cpb %2.2f Mcycles \n", t_cost, m_cost >> 10, thread_n, (float) delta_i / 1024, mcycles_i);
            printf("Argon2id %d pass(es)  %d Mbytes %d threads:  %2.2f cpb %2.2f Mcycles \n", t_cost, m_cost >> 10, thread_n, (float) delta_id / 1024, mcycles_id);
            printf("Argon2ds %d pass(es)  %d Mbytes %d threads:  %2.2f cpb %2.2f Mcycles \n", t_cost, m_cost >> 10, thread_n, (float) delta_ds / 1024, mcycles_ds);

            float run_time = ((float) stop_time - start_time) / (CLOCKS_PER_SEC);
            printf("%2.4f seconds\n\n", run_time);
#endif
        }
    }
}

/*Call the PHS function with certain parameter values.*/

void Run(void *out, size_t outlen, size_t inlen, size_t saltlen, uint32_t t_cost, uint32_t m_cost) {
#ifdef _MEASURE
    uint64_t start_cycles, stop_cycles, delta;
    uint32_t ui1, ui2;

    clock_t start_time = clock();
    start_cycles = rdtscp(&ui1);
#endif

    unsigned char zero_array[256];
    unsigned char one_array[256];

    memset(zero_array, 0, 256);
    memset(one_array, 1, 256);

    PHS(out, outlen, zero_array, inlen, one_array, saltlen, t_cost, m_cost);

#ifdef _MEASURE
    stop_cycles = rdtscp(&ui2);
    clock_t finish_time = clock();

    delta = (stop_cycles - start_cycles) / (m_cost);
    float mcycles = (float) (stop_cycles - start_cycles) / (1 << 20);
    printf("Argon:  %2.2f cpb %2.2f Mcycles ", (float) delta / 1024, mcycles);

    float run_time = ((float) finish_time - start_time) / (CLOCKS_PER_SEC);
    printf("%2.4f seconds\n", run_time);
#endif

}

/*Generate test vectors of Argon2 of type @type*/

void GenerateTestVectors(const std::string &type) {
    const unsigned out_length = 32;
    const unsigned pwd_length = 32;
    const unsigned salt_length = 16;
    const unsigned secret_length = 8;
    const unsigned ad_length = 12;
    bool clear_memory = false;
    bool clear_secret = false;
    bool clear_password = false;
    unsigned char out[out_length];
    unsigned char pwd[pwd_length];
    unsigned char salt[salt_length];
    unsigned char secret[secret_length];
    unsigned char ad[ad_length];
    const AllocateMemoryCallback myown_allocator = NULL;
    const FreeMemoryCallback myown_deallocator = NULL;

    unsigned t_cost = 3;
    unsigned m_cost = 16;
    unsigned lanes = 4;


    memset(pwd, 1, pwd_length);
    memset(salt, 2, salt_length);
    memset(secret, 3, secret_length);
    memset(ad, 4, ad_length);

#if defined(ARGON2_KAT) || defined(ARGON2_KAT_INTERNAL)
    printf("Generate test vectors in file: \"%s\".\n", ARGON2_KAT_FILENAME);
#else
    printf("Enable ARGON2_KAT to generate the test vectors.\n");
#endif

    Argon2_Context context(out, out_length, pwd, pwd_length, salt, salt_length,
            secret, secret_length, ad, ad_length, t_cost, m_cost, lanes,
            myown_allocator, myown_deallocator,
            clear_password, clear_secret, clear_memory);

    if (type == std::string("Argon2d")) {
        printf("Test Argon2d\n");
        Argon2d(&context);
        return;
    }
    if (type == std::string("Argon2i")) {
        printf("Test Argon2i\n");
        Argon2i(&context);
        return;
    }
    if (type == std::string("Argon2ds")) {
        printf("Test Argon2ds\n");
        Argon2ds(&context);
        return;
    }
    if (type == std::string("Argon2id")) {
        printf("Test Argon2id\n");
        Argon2id(&context);
        return;
    }

    printf("Wrong Argon2 type!\n");
}



int main(int argc, char* argv[]) {
   
    unsigned char out[32];

    uint32_t outlen = 32;
    uint32_t m_cost = 1 << 18;
    uint32_t t_cost = 3;
    uint32_t p_len = 16;
    unsigned thread_n = 4;
    uint32_t s_len = 16;

    bool generate_test_vectors = false;
    //char type[argon2_type_length] = "Argon2d";
    std::string type;

#ifdef ARGON2_KAT
    remove(ARGON2_KAT_FILENAME);
#endif

    

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-help") == 0) {
            printf("====================================== \n");
            printf("Argon2 - test implementation \n");
            printf("====================================== \n");
            printf("Options:\n");
            printf("\t -taglength <Tag Length: 0..31>\n");
            printf("\t -logmcost < Base 2 logarithm of m_cost : 0..23 > \n");
            printf("\t -tcost < t_cost : 0..2^24 > \n");
            printf("\t -pwdlen < Password : length>\n");
            printf("\t -saltlen < Salt : Length>\n");
            printf("\t -threads < Number of threads : %u.. %u>\n", ARGON2_MIN_LANES, ARGON2_MAX_LANES);
            printf("\t -type <Argon2d; Argon2ds; Argon2i; Argon2id >\n");
            printf("\t -gen-tv\n");
            printf("\t -benchmark\n");
            printf("\t -help\n");
            printf("If no arguments given, Argon2 is called with default parameters t_cost=%d, m_cost=%d and threads=%d.\n", t_cost, m_cost, thread_n);
            return 0;
        }

        if (strcmp(argv[i], "-taglength") == 0) {
            if (i < argc - 1) {
                i++;
                outlen = ((uint32_t)atoi(argv[i])) % 32;
                continue;
            }
        }

        if (strcmp(argv[i], "-logmcost") == 0) {
            if (i < argc - 1) {
                i++;
                m_cost = (uint8_t) 1 << ((uint8_t)atoi(argv[i]) % 24);
                continue;
            }
        }

        if (strcmp(argv[i], "-tcost") == 0) {
            if (i < argc - 1) {
                i++;
                t_cost = atoi(argv[i]) & 0xffffff;
                continue;
            }
        }

        if (strcmp(argv[i], "-pwdlen") == 0) {
            if (i < argc - 1) {
                i++;
                p_len = atoi(argv[i]) % 160;
                continue;
            }
        }

        if (strcmp(argv[i], "-saltlen") == 0) {
            if (i < argc - 1) {
                i++;
                s_len = atoi(argv[i]) % 32;
                continue;
            }
        }

        if (strcmp(argv[i], "-threads") == 0) {
            if (i < argc - 1) {
                i++;
                thread_n = atoi(argv[i]) % ARGON2_MAX_LANES;
                continue;
            }
        }

        if (strcmp(argv[i], "-type") == 0) {
            if (i < argc - 1) {
                i++;
                type = std::string(argv[i]);
                //                      if (argon2_type_length >= strlen(argv[i])) {
                //                   memcpy(type, argv[i], strlen(argv[i]));
                //              }
                continue;
            }
        }

        if (strcmp(argv[i], "-gen-tv") == 0) {
            generate_test_vectors = true;
            continue;
        }



        if (strcmp(argv[i], "-benchmark") == 0) {
            Benchmark();
            return 0;
        }
    }

    if (generate_test_vectors) {
        GenerateTestVectors(type);
        return 0;
    }
    
    /*No benchmark, no test vectors, just run*/
    
    

    Run(out, outlen, p_len, s_len, t_cost, m_cost);

    return 0;
}
