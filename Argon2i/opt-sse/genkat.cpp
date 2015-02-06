
#include "stdio.h"
#include "stdint.h"
#include <time.h>
#include <vector>
#include <thread>
#include <random>
#include <cstring>
using namespace std;

#if defined(_MSC_VER)
#include "intrin.h"
#else
#include <x86intrin.h>
#endif
#include "emmintrin.h"

#pragma intrinsic(_mm_set_epi64x)  

#include "argon2i.h"
#include "blake2.h"
#define _MEASURE

void GenKat()
{
	unsigned char out[128];
	unsigned char zero_array[256];
	memset(zero_array, 0, 256);
	unsigned char one_array[256];
	memset(one_array, 1, 256);
	unsigned t_cost = 3;
	//unsigned m_cost = 2;
#ifdef KAT
	remove(KAT_FILENAME);
#endif
	for (unsigned m_cost = 1; m_cost <= 1000; m_cost *= 10)
	{

		for (unsigned p_len =16; p_len <=16; p_len += 128)
		{
			for (unsigned s_len = 8; s_len <= 8; s_len += 16)
			{
				for (unsigned thr = 1; thr <= 8; ++thr)
				{
					for (unsigned outlen = 8; outlen <= 8; outlen *= 4)
					{
#ifdef _MEASURE
						uint64_t  i2, i3, d2;
						uint32_t ui2, ui3;
#endif


#ifdef _MEASURE
						clock_t start = clock();
						i2 = __rdtscp(&ui2);
#endif
						Argon2iOpt(out, outlen, zero_array, p_len, one_array, s_len, NULL, 0, NULL, 0, t_cost, m_cost, thr);
#ifdef _MEASURE
						i3 = __rdtscp(&ui3);
						clock_t finish = clock();

						d2 = (i3 - i2) / (m_cost);
						float mcycles = (float)(i3 - i2) / (1 << 20);
						printf("Argon:  %d iterations %2.2f cpb %2.2f Mcycles\n", t_cost, (float)d2 / 1000, mcycles);

						printf("Tag: ");
						for (unsigned i = 0; i < outlen; ++i)
							printf("%2.2x ", ((unsigned char*)out)[i]);
						printf("\n");

						float run_time = ((float)finish - start) / (CLOCKS_PER_SEC);
						printf("%2.4f seconds\n", run_time);
#endif
					}
				}
			}
		}
	}
}

void Benchmark()  //Benchmarks Argon with salt length 16, password length 128, tcost 3, and different threads and mcost
{
	unsigned char out[32];
	int i = 0;
	uint32_t outlen = 16;
	uint32_t t_cost = MIN_TIME;
	uint32_t inlen = 128;
	uint32_t saltlen = 16;

	unsigned char zero_array[256];
	memset(zero_array, 0, 256);
	unsigned char one_array[256];
	memset(one_array, 1, 256);

	for (uint32_t m_cost = (uint32_t)1 << 1; m_cost <= (uint32_t)1 << 22; m_cost *= 2)
	{
		for (uint32_t thread_n = 1; thread_n <= 8; thread_n++)
		{

#ifdef _MEASURE
			uint64_t  i2, i3, d2;
			uint32_t ui2, ui3;
			clock_t start = clock();
			i2 = __rdtscp(&ui2);
#endif

			Argon2iOpt(out, outlen, zero_array, inlen, one_array, saltlen, NULL, 0, NULL, 0, t_cost, m_cost, thread_n);

#ifdef _MEASURE
			i3 = __rdtscp(&ui3);
			clock_t finish = clock();
			d2 = (i3 - i2) / (m_cost);
			float mcycles = (float)(i3 - i2) / (1 << 20);
			printf("Argon2i Opt %d pass(es)  %d Mbytes %d threads:  %2.2f cpb %2.2f Mcycles\n ", t_cost, m_cost >> 10, thread_n, (float)d2 / 1000, mcycles);
			float run_time = ((float)finish - start) / (CLOCKS_PER_SEC);
			//printf("%2.4f seconds\n\n", run_time);
#endif
		}
	}
}

void Run(void *out, uint32_t outlen, uint32_t inlen, uint32_t saltlen,
	uint32_t t_cost, size_t m_cost, uint32_t thread_n)
{
#ifdef _MEASURE
	uint64_t  i2, i3, d2;
	uint32_t ui2, ui3;
	clock_t start = clock();
	i2 = __rdtscp(&ui2);
#endif

	unsigned char zero_array[256];
	memset(zero_array, 0, 256);
	unsigned char one_array[256];
	memset(one_array, 1, 256);

	PHS(out, outlen, zero_array, inlen, one_array, saltlen, t_cost, m_cost);

#ifdef _MEASURE
	i3 = __rdtscp(&ui3);
	clock_t finish = clock();
	d2 = (i3 - i2) / (m_cost);
	float mcycles = (float)(i3 - i2) / (1 << 20);
	printf("Argon:  %2.2f cpb %2.2f Mcycles ", (float)d2 / 1000, mcycles);
	float run_time = ((float)finish - start) / (CLOCKS_PER_SEC);
	printf("%2.4f seconds\n", run_time);
#endif

}

int main(int argc, char* argv[])
{
	unsigned char out[32];
	int i = 0;
	size_t outlen = 32;
	size_t m_cost = 1 << 18;
	uint32_t t_cost = 3;
	size_t p_len = 16;
	unsigned thread_n = 4;
	size_t s_len = 16;

	if (argc == 1)
	{
	//	printf("-taglength <Tag Length 0..31> -logmcost <Base 2 logarithm of m_cost 0..23> -tcost <t_cost 0..2^24> -pwdlen <Password length> -saltlen <Salt Length> -threads <Number of threads 0..31>\n");
	//	printf("No arguments given. Argon is called with default parameters t_cost =3 and m_cost=2. Passwords are substrings of the AES S-box lookup table.\n");
		GenKat();
	}

	else
	{
		for (int i = 1; i< argc; i++)
		{
			if (strcmp(argv[i], "-taglength") == 0)
			{
				if (i<argc - 1)
				{
					i++;
					outlen = atoi(argv[i]) % 32;
					continue;
				}
			}
			if (strcmp(argv[i], "-logmcost") == 0)
			{
				if (i<argc - 1)
				{
					i++;
					m_cost = (size_t)1 << (atoi(argv[i]) % 24);
					continue;
				}
			}
			if (strcmp(argv[i], "-tcost") == 0)
			{
				if (i<argc - 1)
				{
					i++;
					t_cost = atoi(argv[i]) & 0xffffff;
					continue;
				}
			}
			if (strcmp(argv[i], "-pwdlen") == 0)
			{
				if (i<argc - 1)
				{
					i++;
					p_len = atoi(argv[i]) % 160;
					continue;
				}
			}
			if (strcmp(argv[i], "-saltlen") == 0)
			{
				if (i<argc - 1)
				{
					i++;
					s_len = atoi(argv[i]) % 32;
					continue;
				}
			}
			if (strcmp(argv[i], "-threads") == 0)
			{
				if (i<argc - 1)
				{
					i++;
					thread_n = atoi(argv[i]) % 32;
					continue;
				}
			}
			if (strcmp(argv[i], "-benchmark") == 0)
			{
				Benchmark();
				return 0;
			}
		}//end of for
		Run(out, outlen, p_len, s_len, t_cost, m_cost, thread_n);
	}//end of else
	return 0;
}
