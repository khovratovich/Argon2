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


#include <map>
#include <string>


/*For memory wiping*/
#ifdef _MSC_VER
#include "windows.h"
#include "winbase.h" //For SecureZeroMemory
#endif
#if defined __STDC_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#define VC_GE_2005( version )		( version >= 1400 )



#include "argon2.h"
#include "argon2-core.h"


/************************* Error messages *********************************************************************************/

static std::map<Argon2_ErrorCodes, std::string> Argon2_ErrorMessage = {
    {ARGON2_OK, "OK"},

    {ARGON2_OUTPUT_PTR_NULL, "Output pointer is NULL"},

    {ARGON2_OUTPUT_TOO_SHORT, "Output is too short"},
    {ARGON2_OUTPUT_TOO_LONG, "Output is too long"},

    {ARGON2_PWD_TOO_SHORT, "Password is too short"},
    {ARGON2_PWD_TOO_LONG, "Password is too long"},

    {ARGON2_SALT_TOO_SHORT, "Salt is too short"},
    {ARGON2_SALT_TOO_LONG, "Salt is too long"},

    {ARGON2_AD_TOO_SHORT, "Associated data is too short"},
    {ARGON2_AD_TOO_LONG, "Associated date is too long"},

    {ARGON2_SECRET_TOO_SHORT, "Secret is too short"},
    {ARGON2_SECRET_TOO_LONG, "Secret is too long"},

    {ARGON2_TIME_TOO_SMALL, "Time cost is too small"},
    {ARGON2_TIME_TOO_LARGE, "Time cost is too large"},

    {ARGON2_MEMORY_TOO_LITTLE, "Memory cost is too small"},
    {ARGON2_MEMORY_TOO_MUCH, "Memory cost is too large"},

    {ARGON2_LANES_TOO_FEW, "Too few lanes"},
    {ARGON2_LANES_TOO_MANY, "Too many lanes"},

    {ARGON2_PWD_PTR_MISMATCH, "Password pointer is NULL, but password length is not 0"},
    {ARGON2_SALT_PTR_MISMATCH, "Salt pointer is NULL, but salt length is not 0"},
    {ARGON2_SECRET_PTR_MISMATCH, "Secret pointer is NULL, but secret length is not 0"},
    {ARGON2_AD_PTR_MISMATCH, "Associated data pointer is NULL, but ad length is not 0"},

    {ARGON2_MEMORY_ALLOCATION_ERROR, "Memory allocation error"},

    {ARGON2_FREE_MEMORY_CBK_NULL, "The free memory callback is NULL"},
    {ARGON2_ALLOCATE_MEMORY_CBK_NULL, "The allocate memory callback is NULL"},

    {ARGON2_INCORRECT_PARAMETER, "Argon2_Context context is NULL"},
    {ARGON2_INCORRECT_TYPE, "There is no such version of Argon2"},
    
    {ARGON2_OUT_PTR_MISMATCH, "Output pointer mismatch"},
    
    {ARGON2_THREADS_TOO_FEW, "Too few threads"},
    {ARGON2_THREADS_TOO_MANY, "Too many threads"},
};


int hash_argon2i(void *out, size_t outlen, const void *in, size_t inlen,
                 const void *salt, size_t saltlen, unsigned int t_cost,
                 unsigned int m_cost) {
    uint8_t* default_ad_ptr = NULL;
    uint32_t default_ad_length = 0;
    uint8_t* default_secret_ptr = NULL;
    uint32_t default_secret_length = 0;
    uint32_t default_parallelism = 1;
    
    const bool clear_password=true; 
    const bool clear_secret=false; 
    const bool clear_memory=false; 
    
    const bool print_internals=false;
    
    const AllocateMemoryCallback own_allocator=NULL;
    const FreeMemoryCallback own_deallocator=NULL;
    

    Argon2_Context context((uint8_t*) out, (uint32_t) outlen,
            (uint8_t*) in, (uint32_t) inlen,
            (uint8_t*) salt, (uint32_t) saltlen,
            default_ad_ptr, default_ad_length,
            default_secret_ptr, default_secret_length,
            (uint32_t) t_cost, (uint32_t) m_cost, default_parallelism, default_parallelism, own_allocator, 
            own_deallocator,clear_password, clear_secret,clear_memory, print_internals);

    return Argon2Core(&context, Argon2_i);
}

int hash_argon2d(void *out, size_t outlen, const void *in, size_t inlen,
                 const void *salt, size_t saltlen, unsigned int t_cost,
                 unsigned int m_cost) {
    uint8_t* default_ad_ptr = NULL;
    uint32_t default_ad_length = 0;
    uint8_t* default_secret_ptr = NULL;
    uint32_t default_secret_length = 0;
    uint32_t default_parallelism = 1;
    
    const bool clear_password=true; 
    const bool clear_secret=false; 
    const bool clear_memory=false; 
    
    const bool print_internals=false;
    
    const AllocateMemoryCallback own_allocator=NULL;
    const FreeMemoryCallback own_deallocator=NULL;
    

    Argon2_Context context((uint8_t*) out, (uint32_t) outlen,
            (uint8_t*) in, (uint32_t) inlen,
            (uint8_t*) salt, (uint32_t) saltlen,
            default_ad_ptr, default_ad_length,
            default_secret_ptr, default_secret_length,
            (uint32_t) t_cost, (uint32_t) m_cost, default_parallelism, default_parallelism, own_allocator, 
            own_deallocator,clear_password, clear_secret,clear_memory, print_internals);

    return Argon2Core(&context, Argon2_d);
}



int Argon2d(Argon2_Context* context) {
    return Argon2Core(context, Argon2_d);
}

int Argon2i(Argon2_Context* context) {
    return Argon2Core(context, Argon2_i);
}

int Argon2id(Argon2_Context* context) {
    return Argon2Core(context, Argon2_id);
}

int Argon2ds(Argon2_Context* context) {
    return Argon2Core(context, Argon2_ds);
}

int VerifyD(Argon2_Context* context, const char *hash) {
    if (0 == context->outlen || NULL == hash) {
        return ARGON2_OUT_PTR_MISMATCH;
    }

    int result = Argon2Core(context, Argon2_d);
    if (ARGON2_OK != result) {
        return result;
    }

    return 0 == memcmp(hash, context->out, context->outlen);
}

const char* ErrorMessage(int error_code) {
    if (error_code < ARGON2_ERROR_CODES_LENGTH) {
        return Argon2_ErrorMessage[(Argon2_ErrorCodes) error_code].c_str();
    }

    return "Unknown error code.";
}

#if defined(__clang__)
#if __has_attribute(optnone)
#define NOT_OPTIMIZED __attribute__((optnone))
#endif
#elif defined(__GNUC__)
#define GCC_VERSION (__GNUC__ * 10000 \
                    + __GNUC_MINOR__ * 100 \
                    + __GNUC_PATCHLEVEL__)
#if GCC_VERSION >= 40400
#define NOT_OPTIMIZED __attribute__((optimize("O0")))
#endif
#endif
#ifndef NOT_OPTIMIZED
#define NOT_OPTIMIZED
#endif


void NOT_OPTIMIZED secure_wipe_memory(void *v, size_t n) {
#if defined  (_MSC_VER ) &&  VC_GE_2005( _MSC_VER )
    SecureZeroMemory(v, n);
#elif defined memset_s
    memset_s(v, n);
#elif defined( __OpenBSD__ )
    explicit_bzero(memory, size);
#else
    static void* (*const volatile memset_sec)(void*, int, size_t) = &memset;
    memset_sec(v, 0, n);
#endif
}


/* encoding/decoding helpers */

/*
 * Some macros for constant-time comparisons. These work over values in
 * the 0..255 range. Returned value is 0x00 on "false", 0xFF on "true".
 */
#define EQ(x, y) ((((0U - ((unsigned)(x) ^ (unsigned)(y))) >> 8) & 0xFF) ^ 0xFF)
#define GT(x, y) ((((unsigned)(y) - (unsigned)(x)) >> 8) & 0xFF)
#define GE(x, y) (GT(y, x) ^ 0xFF)
#define LT(x, y) GT(y, x)
#define LE(x, y) GE(y, x)

/*
 * Convert value x (0..63) to corresponding Base64 character.
 */
static int b64_byte_to_char(unsigned x) {
    return (LT(x, 26) & (x + 'A')) |
           (GE(x, 26) & LT(x, 52) & (x + ('a' - 26))) |
           (GE(x, 52) & LT(x, 62) & (x + ('0' - 52))) | (EQ(x, 62) & '+') |
           (EQ(x, 63) & '/');
}

/*
 * Convert some bytes to Base64. 'dst_len' is the length (in characters)
 * of the output buffer 'dst'; if that buffer is not large enough to
 * receive the result (including the terminating 0), then (size_t)-1
 * is returned. Otherwise, the zero-terminated Base64 string is written
 * in the buffer, and the output length (counted WITHOUT the terminating
 * zero) is returned.
 */
static size_t to_base64(char *dst, size_t dst_len, const void *src,
                        size_t src_len) {
    size_t olen;
    const unsigned char *buf;
    unsigned acc, acc_len;

    olen = (src_len / 3) << 2;
    switch (src_len % 3) {
    case 2:
        olen++;
    /* fall through */
    case 1:
        olen += 2;
        break;
    }
    if (dst_len <= olen) {
        return (size_t)-1;
    }
    acc = 0;
    acc_len = 0;
    buf = (const unsigned char *)src;
    while (src_len-- > 0) {
        acc = (acc << 8) + (*buf++);
        acc_len += 8;
        while (acc_len >= 6) {
            acc_len -= 6;
            *dst++ = b64_byte_to_char((acc >> acc_len) & 0x3F);
        }
    }
    if (acc_len > 0) {
        *dst++ = b64_byte_to_char((acc << (6 - acc_len)) & 0x3F);
    }
    *dst++ = 0;
    return olen;
}

/* ==================================================================== */
/*
 * Code specific to Argon2i.
 *
 * The code below applies the following format:
 *
 *  $argon2i$m=<num>,t=<num>,p=<num>[,keyid=<bin>][,data=<bin>][$<bin>[$<bin>]]
 *
 * where <num> is a decimal integer (positive, fits in an 'unsigned long')
 * and <bin> is Base64-encoded data (no '=' padding characters, no newline
 * or whitespace). The "keyid" is a binary identifier for a key (up to 8
 * bytes); "data" is associated data (up to 32 bytes). When the 'keyid'
 * (resp. the 'data') is empty, then it is ommitted from the output.
 *
 * The last two binary chunks (encoded in Base64) are, in that order,
 * the salt and the output. Both are optional, but you cannot have an
 * output without a salt. The binary salt length is between 8 and 48 bytes.
 * The output length is always exactly 32 bytes.
 */

int encode_string(char *dst, size_t dst_len, Argon2_Context *ctx) {
#define SS(str)                                                                \
    do {                                                                       \
        size_t pp_len = strlen(str);                                           \
        if (pp_len >= dst_len) {                                               \
            return 0;                                                          \
        }                                                                      \
        memcpy(dst, str, pp_len + 1);                                          \
        dst += pp_len;                                                         \
        dst_len -= pp_len;                                                     \
    } while (0)

#define SX(x)                                                                  \
    do {                                                                       \
        char tmp[30];                                                          \
        sprintf(tmp, "%lu", (unsigned long)(x));                               \
        SS(tmp);                                                               \
    } while (0);

#define SB(buf, len)                                                           \
    do {                                                                       \
        size_t sb_len = to_base64(dst, dst_len, buf, len);                     \
        if (sb_len == (size_t)-1) {                                            \
            return 0;                                                          \
        }                                                                      \
        dst += sb_len;                                                         \
        dst_len -= sb_len;                                                     \
    } while (0);

    SS("$argon2i$m=");
    SX(ctx->m_cost);
    SS(",t=");
    SX(ctx->t_cost);
    SS(",p=");
    SX(ctx->lanes);

    if (ctx->adlen > 0) {
        SS(",data=");
        SB(ctx->ad, ctx->adlen);
    }

    if (ctx->saltlen == 0)
        return 1;

    SS("$");
    SB(ctx->salt, ctx->saltlen);

    if (ctx->outlen == 0)
        return 1;

    SS("$");
    SB(ctx->out, ctx->outlen);
    return 1;

#undef SS
#undef SX
#undef SB
}