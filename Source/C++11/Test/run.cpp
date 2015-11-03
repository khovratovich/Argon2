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
#include <inttypes.h>
#include <random>
#include <cstring>
#include <algorithm>
#include <vector>
#include <string>

#include "time.h"
#include "argon2.h"


void fatal(const char *error) {
    fprintf(stderr, "Error: %s\n", error);
    exit(1);
}

void usage(const char *cmd) {
    printf("Usage:  %s pwd salt [-d] [-t iterations] [-m memory] "
           "[-p parallelism]\n",
           cmd);

    printf("Parameters:\n");
    printf("\tpwd\t\tThe password to hash\n");
    printf("\tsalt\t\tThe salt to use, at most 16 characters\n");
    printf("\t-d\t\tUse Argon2d instead of Argon2i (which is the default)\n");
    printf("\t-t N\t\tSets the number of iterations to N (default = %d)\n",
           ARGON2_T_COST_DEF);
    printf("\t-m N\t\tSets the memory usage of 2^N KiB (default %d)\n",
           ARGON2_LOG_M_COST_DEF);
    printf("\t-p N\t\tSets parallelism to N threads (default %d)\n",
           ARGON2_THREADS_DEF);
}


/*
Runs Argon2 with certain inputs and parameters, inputs not cleared. Prints the
Base64-encoded hash string
@out output array with at least 32 bytes allocated
@pwd NULL-terminated string, presumably from argv[]
@salt salt array with at least SALTLEN_DEF bytes allocated
@t_cost number of iterations
@m_cost amount of requested memory in KB
@lanes amount of requested parallelism
@threads actual parallelism
@type String, only "d" and "i" are accepted
*/
static void Run(uint8_t *out, char *pwd, uint8_t *salt, uint32_t t_cost,
                uint32_t m_cost, uint32_t lanes, uint32_t threads,
                const char *type) {
    clock_t start_time, stop_time;
    
    /*Default parameters*/
    uint32_t out_length=ARGON2_OUT_LEN_DEF;
    uint32_t salt_length=ARGON2_SALT_LEN_DEF;
    uint8_t* secret=NULL;
    uint32_t secret_length=0;
    uint8_t* ad=NULL;
    uint32_t ad_length=0;
    bool clear_memory = false;
    bool clear_secret = false;
    bool clear_password = true;
    bool print_internals = false;
    
    start_time = clock();

    if (!pwd) {
        fatal("password missing");
    }

    if (!salt) {
        secure_wipe_memory(pwd, strlen(pwd));
        fatal("salt missing");
    }

    unsigned pwd_length = strlen(pwd);
    Argon2_Context context(out, out_length, (uint8_t*)pwd, pwd_length, salt, salt_length,
            secret, secret_length, ad, ad_length, t_cost, m_cost, lanes, threads,
            NULL, NULL,
            clear_password, clear_secret, clear_memory, print_internals);
    if (!strcmp(type, "d")) {
        int result = Argon2d(&context);
        if (result != ARGON2_OK)
            fatal(ErrorMessage(result));
    } else if (!strcmp(type, "i")) {
        int result = Argon2i(&context);
        if (result != ARGON2_OK)
            fatal(ErrorMessage(result));
    } else if (!strcmp(type, "id")) {
        int result = Argon2id(&context);
        if (result != ARGON2_OK)
            fatal(ErrorMessage(result));
    } else if (!strcmp(type, "ds")) {
        int result = Argon2ds(&context);
        if (result != ARGON2_OK)
            fatal(ErrorMessage(result));
    } else {
        secure_wipe_memory(pwd, strlen(pwd));
        fatal("wrong Argon2 type");
    }

    stop_time = clock();

    /* add back when proper decoding */
    /*
    char encoded[300];
    encode_string(encoded, sizeof encoded, &context);
    printf("%s\n", encoded);
    */
    printf("Hash:\t\t");
    for (uint32_t i = 0; i < context.outlen; ++i) {
        printf("%02x", context.out[i]);
    }
    printf("\n");

    printf("%2.3f seconds\n",
           ((double)stop_time - start_time) / (CLOCKS_PER_SEC));

}



int main(int argc, char *argv[]) {
    
    unsigned char out[ARGON2_OUT_LEN_DEF];
    uint32_t m_cost = 1 << ARGON2_LOG_M_COST_DEF;
    uint32_t t_cost = ARGON2_T_COST_DEF;
    uint32_t lanes = ARGON2_LANES_DEF;
    uint32_t threads = ARGON2_THREADS_DEF;
    char *pwd = NULL;
    uint8_t salt[ARGON2_SALT_LEN_DEF];
    const char *type = "i";
    int i;

    if (argc < 3) {
        usage(argv[0]);
        return ARGON2_MISSING_ARGS;
    }

    /* get password and salt from command line */
    pwd = argv[1];
    if (strlen(argv[2]) > ARGON2_SALT_LEN_DEF) {
        fatal("salt too long");
    }
    memset(salt, 0x00, ARGON2_SALT_LEN_DEF); /* pad with null bytes */
    memcpy(salt, argv[2], strlen(argv[2]));

    /* parse options */
    for (i = 3; i < argc; i++) {
        const char *a = argv[i];
        unsigned long input = 0;
        if (!strcmp(a, "-m")) {
            if (i < argc - 1) {
                i++;
                input = strtoul(argv[i], NULL, 10);
                if (input == 0 || input == ULONG_MAX ||
                    input > ARGON2_MAX_MEMORY_BITS) {
                    fatal("bad numeric input for -m");
                }
                m_cost = ARGON2_MIN(UINT64_C(1) << input, UINT32_C(0xFFFFFFFF));
                if (m_cost > ARGON2_MAX_MEMORY) {
                    fatal("m_cost overflow");
                }
                continue;
            } else {
                fatal("missing -m argument");
            }
        } else if (!strcmp(a, "-t")) {
            if (i < argc - 1) {
                i++;
                input = strtoul(argv[i], NULL, 10);
                if (input == 0 || input == ULONG_MAX ||
                    input > ARGON2_MAX_TIME) {
                    fatal("bad numeric input for -t");
                }
                t_cost = input;
                continue;
            } else {
                fatal("missing -t argument");
            }
        } else if (!strcmp(a, "-p")) {
            if (i < argc - 1) {
                i++;
                input = strtoul(argv[i], NULL, 10);
                if (input == 0 || input == ULONG_MAX ||
                    input > ARGON2_MAX_THREADS || input > ARGON2_MAX_LANES) {
                    fatal("bad numeric input for -p");
                }
                threads = input;
                lanes = threads;
                continue;
            } else {
                fatal("missing -p argument");
            }
        } else if (!strcmp(a, "-d")) {
            type = "d";
        } else {
            fatal("unknown argument");
        }
    }
    printf("Type:\t\tArgon2%c\n", type[0]);
    printf("Iterations:\t%" PRIu32 " \n", t_cost);
    printf("Memory:\t\t%" PRIu32 " KiB\n", m_cost);
    printf("Parallelism:\t%" PRIu32 " \n", lanes);
    Run(out, pwd, salt, t_cost, m_cost, lanes, threads, type);

    return ARGON2_OK;
}