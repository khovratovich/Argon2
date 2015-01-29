/*Argon2 Reference Implementation
  Code written by Dmitry Khovratovich in 2015.
  khovratovich@gmail.com*/


#include "stdio.h"

//#include "wmmintrin.h"
//#include <immintrin.h> 
#include <intrin.h>
#include <stdint.h>
#include <time.h> 

#include <string>
#include <vector>
#include <thread>
using namespace std;

#include "blake2b-round-perm.h"
#include "blake2.h"
#include "argon2d.h"


void allocate_memory(uint8_t **memory, uint32_t m_cost)
{
	*memory = (uint8_t *)_mm_malloc((size_t)m_cost << 10, ALIGN_ARGON);
	if (!*memory)
	{
		printf("Could not allocate the requested memory!\n");
		exit(1);
	}
}

void free_memory(uint8_t **memory)
{
	if (*memory)
	{
		_mm_free((void *)*memory);
	}
}

void MakeBlock(__m128i* prev_block, uint8_t* ref_block, uint8_t* next_block)
{
	__m128i block2[64];
	__m128i blocktmp[64];
	__m128i t0, t1;

	block2[0] = _mm_load_si128((__m128i *) ref_block);
	block2[1] = _mm_load_si128((__m128i *) (ref_block + 16));
	block2[2] = _mm_load_si128((__m128i *) (ref_block + 32));
	block2[3] = _mm_load_si128((__m128i *) (ref_block + 48));
	block2[4] = _mm_load_si128((__m128i *) (ref_block + 64));
	block2[5] = _mm_load_si128((__m128i *) (ref_block + 80));
	block2[6] = _mm_load_si128((__m128i *) (ref_block + 96));
	block2[7] = _mm_load_si128((__m128i *) (ref_block + 112));
	block2[8] = _mm_load_si128((__m128i *) (ref_block + 128));
	block2[9] = _mm_load_si128((__m128i *) (ref_block + 144));
	block2[10] = _mm_load_si128((__m128i *) (ref_block + 160));
	block2[11] = _mm_load_si128((__m128i *) (ref_block + 176));
	block2[12] = _mm_load_si128((__m128i *) (ref_block + 192));
	block2[13] = _mm_load_si128((__m128i *) (ref_block + 208));
	block2[14] = _mm_load_si128((__m128i *) (ref_block + 224));
	block2[15] = _mm_load_si128((__m128i *) (ref_block + 240));

	block2[16] = _mm_load_si128((__m128i *) (ref_block + 256));
	block2[17] = _mm_load_si128((__m128i *) (ref_block + 272));
	block2[18] = _mm_load_si128((__m128i *) (ref_block + 288));
	block2[19] = _mm_load_si128((__m128i *) (ref_block + 304));
	block2[20] = _mm_load_si128((__m128i *) (ref_block + 320));
	block2[21] = _mm_load_si128((__m128i *) (ref_block + 336));
	block2[22] = _mm_load_si128((__m128i *) (ref_block + 352));
	block2[23] = _mm_load_si128((__m128i *) (ref_block + 368));
	block2[24] = _mm_load_si128((__m128i *) (ref_block + 384));
	block2[25] = _mm_load_si128((__m128i *) (ref_block + 400));
	block2[26] = _mm_load_si128((__m128i *) (ref_block + 416));
	block2[27] = _mm_load_si128((__m128i *) (ref_block + 432));
	block2[28] = _mm_load_si128((__m128i *) (ref_block + 448));
	block2[29] = _mm_load_si128((__m128i *) (ref_block + 464));
	block2[30] = _mm_load_si128((__m128i *) (ref_block + 480));
	block2[31] = _mm_load_si128((__m128i *) (ref_block + 496));


	block2[32] = _mm_load_si128((__m128i *) (ref_block + 512));
	block2[33] = _mm_load_si128((__m128i *) (ref_block + 528));
	block2[34] = _mm_load_si128((__m128i *) (ref_block + 544));
	block2[35] = _mm_load_si128((__m128i *) (ref_block + 560));
	block2[36] = _mm_load_si128((__m128i *) (ref_block + 576));
	block2[37] = _mm_load_si128((__m128i *) (ref_block + 592));
	block2[38] = _mm_load_si128((__m128i *) (ref_block + 608));
	block2[39] = _mm_load_si128((__m128i *) (ref_block + 624));
	block2[40] = _mm_load_si128((__m128i *) (ref_block + 640));
	block2[41] = _mm_load_si128((__m128i *) (ref_block + 656));
	block2[42] = _mm_load_si128((__m128i *) (ref_block + 672));
	block2[43] = _mm_load_si128((__m128i *) (ref_block + 688));
	block2[44] = _mm_load_si128((__m128i *) (ref_block + 704));
	block2[45] = _mm_load_si128((__m128i *) (ref_block + 720));
	block2[46] = _mm_load_si128((__m128i *) (ref_block + 736));
	block2[47] = _mm_load_si128((__m128i *) (ref_block + 752));

	block2[48] = _mm_load_si128((__m128i *) (ref_block + 768));
	block2[49] = _mm_load_si128((__m128i *) (ref_block + 784));
	block2[50] = _mm_load_si128((__m128i *) (ref_block + 800));
	block2[51] = _mm_load_si128((__m128i *) (ref_block + 816));
	block2[52] = _mm_load_si128((__m128i *) (ref_block + 832));
	block2[53] = _mm_load_si128((__m128i *) (ref_block + 848));
	block2[54] = _mm_load_si128((__m128i *) (ref_block + 864));
	block2[55] = _mm_load_si128((__m128i *) (ref_block + 880));
	block2[56] = _mm_load_si128((__m128i *) (ref_block + 896));
	block2[57] = _mm_load_si128((__m128i *) (ref_block + 912));
	block2[58] = _mm_load_si128((__m128i *) (ref_block + 928));
	block2[59] = _mm_load_si128((__m128i *) (ref_block + 944));
	block2[60] = _mm_load_si128((__m128i *) (ref_block + 960));
	block2[61] = _mm_load_si128((__m128i *) (ref_block + 976));
	block2[62] = _mm_load_si128((__m128i *) (ref_block + 992));
	block2[63] = _mm_load_si128((__m128i *) (ref_block + 1008));


	prev_block[0] = _mm_xor_si128(prev_block[0], block2[0]);
	prev_block[1] = _mm_xor_si128(prev_block[1], block2[1]);
	prev_block[2] = _mm_xor_si128(prev_block[2], block2[2]);
	prev_block[3] = _mm_xor_si128(prev_block[3], block2[3]);
	prev_block[4] = _mm_xor_si128(prev_block[4], block2[4]);
	prev_block[5] = _mm_xor_si128(prev_block[5], block2[5]);
	prev_block[6] = _mm_xor_si128(prev_block[6], block2[6]);
	prev_block[7] = _mm_xor_si128(prev_block[7], block2[7]);
	prev_block[8] = _mm_xor_si128(prev_block[8], block2[8]);
	prev_block[9] = _mm_xor_si128(prev_block[9], block2[8]);
	prev_block[10] = _mm_xor_si128(prev_block[10], block2[10]);
	prev_block[11] = _mm_xor_si128(prev_block[11], block2[11]);
	prev_block[12] = _mm_xor_si128(prev_block[12], block2[12]);
	prev_block[13] = _mm_xor_si128(prev_block[13], block2[13]);
	prev_block[14] = _mm_xor_si128(prev_block[14], block2[14]);
	prev_block[15] = _mm_xor_si128(prev_block[15], block2[15]);

	prev_block[16] = _mm_xor_si128(prev_block[16], block2[16]);
	prev_block[17] = _mm_xor_si128(prev_block[17], block2[17]);
	prev_block[18] = _mm_xor_si128(prev_block[18], block2[18]);
	prev_block[19] = _mm_xor_si128(prev_block[19], block2[19]);
	prev_block[20] = _mm_xor_si128(prev_block[20], block2[20]);
	prev_block[21] = _mm_xor_si128(prev_block[21], block2[21]);
	prev_block[22] = _mm_xor_si128(prev_block[22], block2[22]);
	prev_block[23] = _mm_xor_si128(prev_block[23], block2[23]);
	prev_block[24] = _mm_xor_si128(prev_block[24], block2[24]);
	prev_block[25] = _mm_xor_si128(prev_block[25], block2[25]);
	prev_block[26] = _mm_xor_si128(prev_block[26], block2[26]);
	prev_block[27] = _mm_xor_si128(prev_block[27], block2[27]);
	prev_block[28] = _mm_xor_si128(prev_block[28], block2[28]);
	prev_block[29] = _mm_xor_si128(prev_block[29], block2[29]);
	prev_block[30] = _mm_xor_si128(prev_block[30], block2[30]);
	prev_block[31] = _mm_xor_si128(prev_block[31], block2[31]);


	prev_block[32] = _mm_xor_si128(prev_block[32], block2[32]);
	prev_block[33] = _mm_xor_si128(prev_block[33], block2[33]);
	prev_block[34] = _mm_xor_si128(prev_block[34], block2[34]);
	prev_block[35] = _mm_xor_si128(prev_block[35], block2[35]);
	prev_block[36] = _mm_xor_si128(prev_block[36], block2[36]);
	prev_block[37] = _mm_xor_si128(prev_block[37], block2[37]);
	prev_block[38] = _mm_xor_si128(prev_block[38], block2[38]);
	prev_block[39] = _mm_xor_si128(prev_block[39], block2[39]);
	prev_block[40] = _mm_xor_si128(prev_block[40], block2[40]);
	prev_block[41] = _mm_xor_si128(prev_block[41], block2[41]);
	prev_block[42] = _mm_xor_si128(prev_block[42], block2[42]);
	prev_block[43] = _mm_xor_si128(prev_block[43], block2[43]);
	prev_block[44] = _mm_xor_si128(prev_block[44], block2[44]);
	prev_block[45] = _mm_xor_si128(prev_block[45], block2[45]);
	prev_block[46] = _mm_xor_si128(prev_block[46], block2[46]);
	prev_block[47] = _mm_xor_si128(prev_block[47], block2[47]);

	prev_block[48] = _mm_xor_si128(prev_block[48], block2[48]);
	prev_block[49] = _mm_xor_si128(prev_block[49], block2[49]);
	prev_block[50] = _mm_xor_si128(prev_block[50], block2[50]);
	prev_block[51] = _mm_xor_si128(prev_block[51], block2[51]);
	prev_block[52] = _mm_xor_si128(prev_block[52], block2[52]);
	prev_block[53] = _mm_xor_si128(prev_block[53], block2[53]);
	prev_block[54] = _mm_xor_si128(prev_block[54], block2[54]);
	prev_block[55] = _mm_xor_si128(prev_block[55], block2[55]);
	prev_block[56] = _mm_xor_si128(prev_block[56], block2[56]);
	prev_block[57] = _mm_xor_si128(prev_block[57], block2[57]);
	prev_block[58] = _mm_xor_si128(prev_block[58], block2[58]);
	prev_block[59] = _mm_xor_si128(prev_block[59], block2[59]);
	prev_block[60] = _mm_xor_si128(prev_block[60], block2[60]);
	prev_block[61] = _mm_xor_si128(prev_block[61], block2[61]);
	prev_block[62] = _mm_xor_si128(prev_block[62], block2[62]);
	prev_block[63] = _mm_xor_si128(prev_block[63], block2[63]);

#ifdef FEEDBACK
	memcpy(blocktmp, prev_block, 64 * sizeof(__m128i));
#endif 

	// BLAKE2 - begin

	BLAKE2_ROUND_NOMSG(prev_block[0], prev_block[1], prev_block[2], prev_block[3],
		prev_block[4], prev_block[5], prev_block[6], prev_block[7]);

	BLAKE2_ROUND_NOMSG(prev_block[8], prev_block[9], prev_block[10], prev_block[11],
		prev_block[12], prev_block[13], prev_block[14], prev_block[15]);

	BLAKE2_ROUND_NOMSG(prev_block[16], prev_block[17], prev_block[18], prev_block[19],
		prev_block[20], prev_block[21], prev_block[22], prev_block[23]);

	BLAKE2_ROUND_NOMSG(prev_block[24], prev_block[25], prev_block[26], prev_block[27],
		prev_block[28], prev_block[29], prev_block[30], prev_block[31]);

	BLAKE2_ROUND_NOMSG(prev_block[32], prev_block[33], prev_block[34], prev_block[35],
		prev_block[36], prev_block[37], prev_block[38], prev_block[39]);

	BLAKE2_ROUND_NOMSG(prev_block[40], prev_block[41], prev_block[42], prev_block[43],
		prev_block[44], prev_block[45], prev_block[46], prev_block[47]);

	BLAKE2_ROUND_NOMSG(prev_block[48], prev_block[49], prev_block[50], prev_block[51],
		prev_block[52], prev_block[53], prev_block[54], prev_block[55]);

	BLAKE2_ROUND_NOMSG(prev_block[56], prev_block[57], prev_block[58], prev_block[59],
		prev_block[60], prev_block[61], prev_block[62], prev_block[63]);


	BLAKE2_ROUND_NOMSG(prev_block[0], prev_block[8], prev_block[16], prev_block[24],
		prev_block[32], prev_block[40], prev_block[48], prev_block[56]);

	BLAKE2_ROUND_NOMSG(prev_block[1], prev_block[9], prev_block[17], prev_block[25],
		prev_block[33], prev_block[41], prev_block[49], prev_block[57]);

	BLAKE2_ROUND_NOMSG(prev_block[2], prev_block[10], prev_block[18], prev_block[26],
		prev_block[34], prev_block[42], prev_block[50], prev_block[58]);

	BLAKE2_ROUND_NOMSG(prev_block[3], prev_block[11], prev_block[19], prev_block[27],
		prev_block[35], prev_block[43], prev_block[51], prev_block[59]);

	BLAKE2_ROUND_NOMSG(prev_block[4], prev_block[12], prev_block[20], prev_block[28],
		prev_block[36], prev_block[44], prev_block[52], prev_block[60]);

	BLAKE2_ROUND_NOMSG(prev_block[5], prev_block[13], prev_block[21], prev_block[29],
		prev_block[37], prev_block[45], prev_block[53], prev_block[61]);

	BLAKE2_ROUND_NOMSG(prev_block[6], prev_block[14], prev_block[22], prev_block[30],
		prev_block[38], prev_block[46], prev_block[54], prev_block[62]);

	BLAKE2_ROUND_NOMSG(prev_block[7], prev_block[15], prev_block[23], prev_block[31],
		prev_block[39], prev_block[47], prev_block[55], prev_block[63]);

	// BLAKE2 - end

#ifdef FEEDBACK
	prev_block[0] = _mm_xor_si128(prev_block[0], blocktmp[0]);
	prev_block[1] = _mm_xor_si128(prev_block[1], blocktmp[1]);
	prev_block[2] = _mm_xor_si128(prev_block[2], blocktmp[2]);
	prev_block[3] = _mm_xor_si128(prev_block[3], blocktmp[3]);
	prev_block[4] = _mm_xor_si128(prev_block[4], blocktmp[4]);
	prev_block[5] = _mm_xor_si128(prev_block[5], blocktmp[5]);
	prev_block[6] = _mm_xor_si128(prev_block[6], blocktmp[6]);
	prev_block[7] = _mm_xor_si128(prev_block[7], blocktmp[7]);
	prev_block[8] = _mm_xor_si128(prev_block[8], blocktmp[8]);
	prev_block[9] = _mm_xor_si128(prev_block[9], blocktmp[8]);
	prev_block[10] = _mm_xor_si128(prev_block[10], blocktmp[10]);
	prev_block[11] = _mm_xor_si128(prev_block[11], blocktmp[11]);
	prev_block[12] = _mm_xor_si128(prev_block[12], blocktmp[12]);
	prev_block[13] = _mm_xor_si128(prev_block[13], blocktmp[13]);
	prev_block[14] = _mm_xor_si128(prev_block[14], blocktmp[14]);
	prev_block[15] = _mm_xor_si128(prev_block[15], blocktmp[15]);

	prev_block[16] = _mm_xor_si128(prev_block[16], blocktmp[16]);
	prev_block[17] = _mm_xor_si128(prev_block[17], blocktmp[17]);
	prev_block[18] = _mm_xor_si128(prev_block[18], blocktmp[18]);
	prev_block[19] = _mm_xor_si128(prev_block[19], blocktmp[19]);
	prev_block[20] = _mm_xor_si128(prev_block[20], blocktmp[20]);
	prev_block[21] = _mm_xor_si128(prev_block[21], blocktmp[21]);
	prev_block[22] = _mm_xor_si128(prev_block[22], blocktmp[22]);
	prev_block[23] = _mm_xor_si128(prev_block[23], blocktmp[23]);
	prev_block[24] = _mm_xor_si128(prev_block[24], blocktmp[24]);
	prev_block[25] = _mm_xor_si128(prev_block[25], blocktmp[25]);
	prev_block[26] = _mm_xor_si128(prev_block[26], blocktmp[26]);
	prev_block[27] = _mm_xor_si128(prev_block[27], blocktmp[27]);
	prev_block[28] = _mm_xor_si128(prev_block[28], blocktmp[28]);
	prev_block[29] = _mm_xor_si128(prev_block[29], blocktmp[29]);
	prev_block[30] = _mm_xor_si128(prev_block[30], blocktmp[30]);
	prev_block[31] = _mm_xor_si128(prev_block[31], blocktmp[31]);


	prev_block[32] = _mm_xor_si128(prev_block[32], blocktmp[32]);
	prev_block[33] = _mm_xor_si128(prev_block[33], blocktmp[33]);
	prev_block[34] = _mm_xor_si128(prev_block[34], blocktmp[34]);
	prev_block[35] = _mm_xor_si128(prev_block[35], blocktmp[35]);
	prev_block[36] = _mm_xor_si128(prev_block[36], blocktmp[36]);
	prev_block[37] = _mm_xor_si128(prev_block[37], blocktmp[37]);
	prev_block[38] = _mm_xor_si128(prev_block[38], blocktmp[38]);
	prev_block[39] = _mm_xor_si128(prev_block[39], blocktmp[39]);
	prev_block[40] = _mm_xor_si128(prev_block[40], blocktmp[40]);
	prev_block[41] = _mm_xor_si128(prev_block[41], blocktmp[41]);
	prev_block[42] = _mm_xor_si128(prev_block[42], blocktmp[42]);
	prev_block[43] = _mm_xor_si128(prev_block[43], blocktmp[43]);
	prev_block[44] = _mm_xor_si128(prev_block[44], blocktmp[44]);
	prev_block[45] = _mm_xor_si128(prev_block[45], blocktmp[45]);
	prev_block[46] = _mm_xor_si128(prev_block[46], blocktmp[46]);
	prev_block[47] = _mm_xor_si128(prev_block[47], blocktmp[47]);

	prev_block[48] = _mm_xor_si128(prev_block[48], blocktmp[48]);
	prev_block[49] = _mm_xor_si128(prev_block[49], blocktmp[49]);
	prev_block[50] = _mm_xor_si128(prev_block[50], blocktmp[50]);
	prev_block[51] = _mm_xor_si128(prev_block[51], blocktmp[51]);
	prev_block[52] = _mm_xor_si128(prev_block[52], blocktmp[52]);
	prev_block[53] = _mm_xor_si128(prev_block[53], blocktmp[53]);
	prev_block[54] = _mm_xor_si128(prev_block[54], blocktmp[54]);
	prev_block[55] = _mm_xor_si128(prev_block[55], blocktmp[55]);
	prev_block[56] = _mm_xor_si128(prev_block[56], blocktmp[56]);
	prev_block[57] = _mm_xor_si128(prev_block[57], blocktmp[57]);
	prev_block[58] = _mm_xor_si128(prev_block[58], blocktmp[58]);
	prev_block[59] = _mm_xor_si128(prev_block[59], blocktmp[59]);
	prev_block[60] = _mm_xor_si128(prev_block[60], blocktmp[60]);
	prev_block[61] = _mm_xor_si128(prev_block[61], blocktmp[61]);
	prev_block[62] = _mm_xor_si128(prev_block[62], blocktmp[62]);
	prev_block[63] = _mm_xor_si128(prev_block[63], blocktmp[63]);
#endif


	_mm_store_si128((__m128i *) next_block, prev_block[0]);
	_mm_store_si128((__m128i *) next_block + 16, prev_block[1]);
	_mm_store_si128((__m128i *) (next_block + 32), prev_block[2]);
	_mm_store_si128((__m128i *) (next_block + 48), prev_block[3]);
	_mm_store_si128((__m128i *) (next_block + 64), prev_block[4]);
	_mm_store_si128((__m128i *) (next_block + 80), prev_block[5]);
	_mm_store_si128((__m128i *) (next_block + 96), prev_block[6]);
	_mm_store_si128((__m128i *) (next_block + 112), prev_block[7]);
	_mm_store_si128((__m128i *) (next_block + 128), prev_block[8]);
	_mm_store_si128((__m128i *) (next_block + 144), prev_block[9]);
	_mm_store_si128((__m128i *) (next_block + 160), prev_block[10]);
	_mm_store_si128((__m128i *) (next_block + 176), prev_block[11]);
	_mm_store_si128((__m128i *) (next_block + 192), prev_block[12]);
	_mm_store_si128((__m128i *) (next_block + 208), prev_block[13]);
	_mm_store_si128((__m128i *) (next_block + 224), prev_block[14]);
	_mm_store_si128((__m128i *) (next_block + 240), prev_block[15]);

	_mm_store_si128((__m128i *) (next_block + 256), prev_block[16]);
	_mm_store_si128((__m128i *) (next_block + 272), prev_block[17]);
	_mm_store_si128((__m128i *) (next_block + 288), prev_block[18]);
	_mm_store_si128((__m128i *) (next_block + 304), prev_block[19]);
	_mm_store_si128((__m128i *) (next_block + 320), prev_block[20]);
	_mm_store_si128((__m128i *) (next_block + 336), prev_block[21]);
	_mm_store_si128((__m128i *) (next_block + 352), prev_block[22]);
	_mm_store_si128((__m128i *) (next_block + 368), prev_block[23]);
	_mm_store_si128((__m128i *) (next_block + 384), prev_block[24]);
	_mm_store_si128((__m128i *) (next_block + 400), prev_block[25]);
	_mm_store_si128((__m128i *) (next_block + 416), prev_block[26]);
	_mm_store_si128((__m128i *) (next_block + 432), prev_block[27]);
	_mm_store_si128((__m128i *) (next_block + 448), prev_block[28]);
	_mm_store_si128((__m128i *) (next_block + 464), prev_block[29]);
	_mm_store_si128((__m128i *) (next_block + 480), prev_block[30]);
	_mm_store_si128((__m128i *) (next_block + 496), prev_block[31]);


	_mm_store_si128((__m128i *) (next_block + 512), prev_block[32]);
	_mm_store_si128((__m128i *) (next_block + 528), prev_block[33]);
	_mm_store_si128((__m128i *) (next_block + 544), prev_block[34]);
	_mm_store_si128((__m128i *) (next_block + 560), prev_block[35]);
	_mm_store_si128((__m128i *) (next_block + 576), prev_block[36]);
	_mm_store_si128((__m128i *) (next_block + 592), prev_block[37]);
	_mm_store_si128((__m128i *) (next_block + 608), prev_block[38]);
	_mm_store_si128((__m128i *) (next_block + 624), prev_block[39]);
	_mm_store_si128((__m128i *) (next_block + 640), prev_block[40]);
	_mm_store_si128((__m128i *) (next_block + 656), prev_block[41]);
	_mm_store_si128((__m128i *) (next_block + 672), prev_block[42]);
	_mm_store_si128((__m128i *) (next_block + 688), prev_block[43]);
	_mm_store_si128((__m128i *) (next_block + 704), prev_block[44]);
	_mm_store_si128((__m128i *) (next_block + 720), prev_block[45]);
	_mm_store_si128((__m128i *) (next_block + 736), prev_block[46]);
	_mm_store_si128((__m128i *) (next_block + 752), prev_block[47]);

	_mm_store_si128((__m128i *) (next_block + 768), prev_block[48]);
	_mm_store_si128((__m128i *) (next_block + 784), prev_block[49]);
	_mm_store_si128((__m128i *) (next_block + 800), prev_block[50]);
	_mm_store_si128((__m128i *) (next_block + 816), prev_block[51]);
	_mm_store_si128((__m128i *) (next_block + 832), prev_block[52]);
	_mm_store_si128((__m128i *) (next_block + 848), prev_block[53]);
	_mm_store_si128((__m128i *) (next_block + 864), prev_block[54]);
	_mm_store_si128((__m128i *) (next_block + 880), prev_block[55]);
	_mm_store_si128((__m128i *) (next_block + 896), prev_block[56]);
	_mm_store_si128((__m128i *) (next_block + 912), prev_block[57]);
	_mm_store_si128((__m128i *) (next_block + 928), prev_block[58]);
	_mm_store_si128((__m128i *) (next_block + 944), prev_block[59]);
	_mm_store_si128((__m128i *) (next_block + 960), prev_block[60]);
	_mm_store_si128((__m128i *) (next_block + 976), prev_block[61]);
	_mm_store_si128((__m128i *) (next_block + 992), prev_block[62]);
	_mm_store_si128((__m128i *)	(next_block + 1008), prev_block[63]);
}



void FillSlice(uint8_t* state, uint32_t m_cost, uint8_t lanes, uint32_t round, uint8_t lane, uint8_t slice)//Filling "slice" in "lane" and "round"
{
	uint32_t slice_length = m_cost /(lanes* (uint32_t)SYNC_POINTS);   //Computing length of the slice

	uint32_t reference_area_size;//Number of blocks outside of the slice to reference
	/*Computing number of blocks to reference, except current slice*/
	if (round == 0)
	{
		reference_area_size = lanes*slice*slice_length;
	}
	else
		reference_area_size = lanes*(SYNC_POINTS-1)*slice_length;
	
	//Filling blocks, preparing macro for referencing blocks in memory
#define BLOCK_PTR(l,s,i) (state+((i)+(s)*slice_length+(l)*slice_length*lanes)*BYTES_IN_BLOCK)

	uint32_t pseudo_rand, ref_index, ref_lane, ref_slice;
	__m128i prev_block[64];  //previous block
	for (uint32_t i = 0; i < slice_length; ++i)
	{
		if ((round == 0) && (slice == 0) && (i < 2)) //skip first two blocks
			continue;
		
		/*1. Computing the reference block*/
		/*1.1 Taking pseudo-random value from the previous block */
		if (i == 0)
		{
			if (slice == 0)
				pseudo_rand = *(uint32_t*)BLOCK_PTR(lane, SYNC_POINTS - 1, slice_length - 1);
			else pseudo_rand = *(uint32_t*)BLOCK_PTR(lane, slice - 1, slice_length - 1);
		}
		else pseudo_rand = *(uint32_t*)BLOCK_PTR(lane, slice, i - 1);
		/*1.2 Computing reference block location*/
		pseudo_rand %= (reference_area_size + i);
		if (pseudo_rand>reference_area_size)
		{
			ref_index = pseudo_rand - reference_area_size;
			ref_slice = slice;
			ref_lane = lane;
		}
		else //Reference block is in other slices, in all lanes
		{
			ref_lane = pseudo_rand / (SYNC_POINTS*slice_length);
			ref_index = pseudo_rand%slice_length;
			/*Number of available slices per lane is different for r==0 and others*/
			uint32_t available_slices = (round == 0) ? slice : (SYNC_POINTS - 1);
			ref_slice = (pseudo_rand / slice_length) % available_slices;
			if (ref_slice >= slice) //This means we refer to next lanes in a previous pass
				ref_slice++;
		}
		/*2.Creating a new block*/
		uint8_t* ref_block = BLOCK_PTR(ref_lane,ref_slice,ref_index);  //random block from memory
		if ((round == 0) && (slice == 0) && (i == 2))
			memcpy(prev_block, BLOCK_PTR(lane, 0, 1),BYTES_IN_BLOCK);
		if (i == 0)//not round 0, slice 0
		{
			if (slice == 0)
				memcpy(prev_block, BLOCK_PTR(lane, SYNC_POINTS - 1, slice_length - 1), BYTES_IN_BLOCK);
			else memcpy(prev_block, BLOCK_PTR(lane, slice - 1, slice_length - 1), BYTES_IN_BLOCK);
		}
		uint8_t* next_block = BLOCK_PTR(lane, slice, i);
		MakeBlock(prev_block, ref_block, next_block);  //Create new block
		
	}

}


int Argon2dOpt(uint8_t *out, uint32_t outlen, const uint8_t *msg, uint32_t msglen, const uint8_t *nonce, uint32_t noncelen, const uint8_t *secret,
	uint8_t secretlen, const uint8_t *ad, uint32_t adlen, uint32_t t_cost, uint32_t m_cost, uint8_t lanes)
{
	if (outlen>MAX_OUTLEN)
		outlen = MAX_OUTLEN;
	if (outlen < MIN_OUTLEN)
		return -1;  //Tag too short

	if (msglen> MAX_MSG)
		msglen = MAX_MSG;
	if (msglen < MIN_MSG)
		return -2; //Password too short

	if (noncelen < MIN_NONCE)
		return -3; //Salt too short
	if (noncelen> MAX_NONCE)
		noncelen = MAX_NONCE;

	if (secretlen> MAX_SECRET)
		secretlen = MAX_SECRET;
	if (secretlen < MIN_SECRET)
		return -4; //Secret too short

	if (adlen> MAX_AD)
		adlen = MAX_AD;
	if (adlen < MIN_AD)
		return -5; //Associated data too short

	//minumum m_cost =8L blocks, where L is the number of lanes
	if (m_cost < 2 * SYNC_POINTS*lanes)
		m_cost=2 * SYNC_POINTS*lanes;
	if (m_cost>MAX_MEMORY)
		m_cost = MAX_MEMORY;

	//minimum t_cost =3
	if (t_cost<MIN_TIME)
		t_cost = MIN_TIME;

	if (lanes<MIN_LANES)
		lanes = MIN_LANES;
	if (lanes>m_cost / BLOCK_SIZE_KILOBYTE)
		lanes = m_cost / BLOCK_SIZE_KILOBYTE;

	printf("Argon2d called, %d m_cost %d lanes\n", m_cost, lanes);

	//Initial hashing
	__m128i blockhash[64];
	memset(blockhash, 0, 64 * sizeof(__m128i)); //H_0 in the document
	uint8_t version = VERSION_NUMBER;
	blake2b_state BlakeHash;
	blake2b_init(&BlakeHash, 32);

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
	

	blake2b_final(&BlakeHash, (uint8_t*)blockhash, 32);

	//Memory allocation
	uint8_t* state;  
	m_cost = (m_cost / (lanes*SYNC_POINTS))*(lanes*SYNC_POINTS); //Ensure that all slices have equal length;
	allocate_memory(&state, m_cost);

	/***Memory fill*/
	//Creating first blocks, we always have at least two blocks in a slice
	uint8_t blockcounter[1024];
	memset(blockcounter, 0, 64 * sizeof(__m128i));
	for (uint8_t l = 0; l < lanes; ++l)
	{
		((uint32_t*)blockcounter)[1] = l;
		((uint32_t*)blockcounter)[0] = 0;
		MakeBlock(blockhash, blockcounter, state + l*(m_cost / lanes)*BYTES_IN_BLOCK);
		((uint32_t*)blockcounter)[0] = 1;
		MakeBlock(blockhash, blockcounter, state + (l*(m_cost / lanes)+1)*BYTES_IN_BLOCK);
	}
	memset(blockhash, 0, 64 * sizeof(__m128i));
	//Creating other blocks
	vector<thread> Threads;
	for (uint8_t r = 0; r < t_cost; ++r)
	{
		for (uint8_t s = 0; s < SYNC_POINTS; ++s)
		{
			for (uint8_t l = 0; l < lanes; ++l)
			{
				Threads.push_back(thread(FillSlice,state,  m_cost, lanes, r,l,s));
			}
			for (auto& th : Threads)
				th.join();
			Threads.clear();
		}
	}
	

	/*3. Finalization*/
	for (uint8_t l = 0; l < lanes; ++l)
	{
		for (unsigned j = 0; j < 64; ++j)
			blockhash[j] = _mm_xor_si128(blockhash[j], *(__m128i*)(state + ((l + 1)*(m_cost / lanes) - 1)*BYTES_IN_BLOCK + 16*j));
	}

	uint8_t tag_buffer[32];

	blake2b_init(&BlakeHash, 32);
	blake2b_update(&BlakeHash, (const uint8_t*)&blockhash, BYTES_IN_BLOCK);

	uint8_t* out_flex = out;
	uint32_t outlen_flex = outlen;
	while (outlen_flex > 16)//Outputting 16 bytes at a time
	{
		blake2b_final(&BlakeHash, tag_buffer, 32);
		memcpy(out_flex, tag_buffer, 16);
		out_flex += 16;
		outlen_flex -= 16;
		blake2b_init(&BlakeHash, 32);
		blake2b_update(&BlakeHash, tag_buffer, 32);
	}
	blake2b_final(&BlakeHash, tag_buffer, outlen_flex);
	memcpy(out_flex, tag_buffer, outlen_flex);
	memset(tag_buffer, 0, 32);

	free_memory(&state);

	return 0;
}

int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, uint32_t  saltlen,
	uint32_t t_cost, uint32_t m_cost)
{
	return Argon2dOpt((uint8_t*)out, outlen, (const uint8_t*)in, inlen, (const uint8_t*)salt, saltlen, NULL, 0, NULL, 0, t_cost, m_cost, 1);
}
