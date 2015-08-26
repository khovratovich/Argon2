/*
 * Argon2 source code package
 * 
 * This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
 * 
 * You should have received a copy of the CC0 Public Domain Dedication along with
 * this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */


#include <stdint.h>

#include "argon2.h"
#include "argon2-core.h"

int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost) {
    uint8_t* default_ad_ptr = NULL;
    uint32_t default_ad_length = 0;
    uint8_t* default_secret_ptr = NULL;
    uint32_t default_secret_length = 0;
    uint8_t default_parallelism = 1;

    Argon2_Context context((uint8_t*) out, (uint32_t) outlen,
            (uint8_t*) in, (uint32_t) inlen,
            (uint8_t*) salt, (uint32_t) saltlen,
            default_ad_ptr, default_ad_length,
            default_secret_ptr, default_secret_length,
            (uint32_t) t_cost, (uint32_t) m_cost, default_parallelism);

    return Argon2Core(&context, Argon2_d);
}

int Argon2d(Argon2_Context* context) {
    return Argon2Core(context, Argon2_d);
}

int Argon2i(Argon2_Context* context) {
    return Argon2Core(context, Argon2_i);
}

int Argon2di(Argon2_Context* context) {
    return Argon2Core(context, Argon2_di);
}

int Argon2id(Argon2_Context* context) {
    return Argon2Core(context, Argon2_id);
}

int Argon2ds(Argon2_Context* context) {
	return Argon2Core(context, Argon2_ds);
}

bool VerifyD(Argon2_Context* context, const char *hash) {
    if (0 == context->outlen || NULL == hash) {
        return false;
    }

    int result = Argon2Core(context, Argon2_d);
    if (ARGON2_OK != result) {
        return false;
    }

    return 0 == memcmp(hash, context->out, context->outlen);
}

const char* ErrorMessage(int error_code) {
    if (error_code < ARGON2_ERROR_CODES_LENGTH) {
        return Argon2_ErrorMessage[error_code];
    }

    return "Unknown error code.";
}
