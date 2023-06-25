//============================================================================
// Name        : Sha1.cpp
// Author      : Hannan
// Version     :
// Copyright   : GPL
// Description : Hello World in C++, Ansi-style
//============================================================================

/*************************** HEADER FILES ***************************/
#include <stdlib.h>
#include <memory.h>


/****************************** MACROS ******************************/
#define ROTLEFT(a, b) ((a << b) | (a >> (32 - b)))

#define SHA1_BLOCK_SIZE 20              // SHA1 outputs a 20 byte digest

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[5];
	WORD k[4];
} SHA1_CTX;

/*********************** FUNCTION DEFINITIONS ***********************/
__device__ void copyinInt(unsigned char* in, unsigned char* in2)
{
	in[0] = in2[3];
	in[1] = in2[2];
	in[2] = in2[1];
	in[3] = in2[0];

	in[4] = in2[7];
	in[5] = in2[6];
	in[6] = in2[5];
	in[7] = in2[4];

	in[8] = in2[11];
	in[9] = in2[10];
	in[10] = in2[9];
	in[11] = in2[8];

	in[12] = in2[15];
	in[13] = in2[14];
	in[14] = in2[13];
	in[15] = in2[12];

	in[16] = in2[19];
	in[17] = in2[18];
	in[18] = in2[17];
	in[19] = in2[16];

	in[20] = in2[23];
	in[21] = in2[22];
	in[22] = in2[21];
	in[23] = in2[20];

	in[24] = in2[27];
	in[25] = in2[26];
	in[26] = in2[25];
	in[27] = in2[24];

	in[28] = in2[31];
	in[29] = in2[30];
	in[30] = in2[29];
	in[31] = in2[28];

	in[32] = in2[35];
	in[33] = in2[34];
	in[34] = in2[33];
	in[35] = in2[32];

	in[36] = in2[39];
	in[37] = in2[38];
	in[38] = in2[37];
	in[39] = in2[36];

	in[40] = in2[43];
	in[41] = in2[42];
	in[42] = in2[41];
	in[43] = in2[40];

	in[44] = in2[47];
	in[45] = in2[46];
	in[46] = in2[45];
	in[47] = in2[44];

	in[48] = in2[51];
	in[49] = in2[50];
	in[50] = in2[49];
	in[51] = in2[48];

	in[52] = in2[55];
	in[53] = in2[54];
	in[54] = in2[53];
	in[55] = in2[52];

	in[56] = in2[59];
	in[57] = in2[58];
	in[58] = in2[57];
	in[59] = in2[56];

	in[60] = in2[63];
	in[61] = in2[62];
	in[62] = in2[61];
	in[63] = in2[60];

}


__device__ void sha1_transform(SHA1_CTX *ctx, const BYTE data[])
{
	WORD a, b, c, d, e, i, j, t, m[80];

	copyinInt((unsigned char*)m, (unsigned char*)data);


	for (i=16 ; i < 80; ++i) {
		m[i] = (m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16]);
		m[i] = (m[i] << 1) | (m[i] >> 31);
	}

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];

#pragma unroll 20
	for (i = 0; i < 20; ++i) {
		t = ROTLEFT(a, 5) + ((b & c) ^ (~b & d)) + e + ctx->k[0] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
#pragma unroll 20
	for ( ; i < 40; ++i) {
		t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[1] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
#pragma unroll 20
	for ( ; i < 60; ++i) {
		t = ROTLEFT(a, 5) + ((b & c) ^ (b & d) ^ (c & d))  + e + ctx->k[2] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
#pragma unroll 20
	for ( ; i < 80; ++i) {
		t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[3] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
}


__device__ void sha1_init(SHA1_CTX *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xc3d2e1f0;
	ctx->k[0] = 0x5a827999;
	ctx->k[1] = 0x6ed9eba1;
	ctx->k[2] = 0x8f1bbcdc;
	ctx->k[3] = 0xca62c1d6;
}


__device__ void sha1_update(SHA1_CTX *ctx, const BYTE data[], size_t len)
{
	int i = 0;
	int OptLen = ctx->datalen + len;

	for (i = 0; i < int(OptLen/64); ++i) {
		memcpy(&ctx->data[ctx->datalen], &data[(i*64)], 64);
		sha1_transform(ctx, ctx->data);
		ctx->bitlen += 512;
		ctx->datalen = 0;
	}

	if((OptLen%64) > 0){
		memcpy(&ctx->data[ctx->datalen], &data[(i*64)], int(OptLen%64));
		ctx->datalen = OptLen%64;
	}

}
__device__ void copyfunc8(unsigned char* a, unsigned char* b){

	a[7] = b[0];
	a[6] = b[1];
	a[5] = b[2];
	a[4] = b[3];
	a[3] = b[4];
	a[2] = b[5];
	a[1] = b[6];
	a[0] = b[7];

	return;
}

__device__ void copyfunc20(unsigned char*a, unsigned char*b){

	a[3] = b[0];
	a[2] = b[1];
	a[1] = b[2];
	a[0] = b[3];

	a[7] = b[4];
	a[6] = b[5];
	a[5] = b[6];
	a[4] = b[7];

	a[11] = b[8];
	a[10] = b[9];
	a[9] = b[10];
	a[8] = b[11];

	a[15] = b[12];
	a[14] = b[13];
	a[13] = b[14];
	a[12] = b[15];

	a[19] = b[16];
	a[18] = b[17];
	a[17] = b[18];
	a[16] = b[19];


	return;
}

__device__ void sha1_final(SHA1_CTX *ctx, BYTE hash[])
{
	WORD i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;

		memset(&ctx->data[i],0,56-i);

	}
	else {
		ctx->data[i++] = 0x80;
		memset(&ctx->data[i],0,64-i);

		sha1_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	copyfunc8(&ctx->data[56], (unsigned char*)&ctx->bitlen);

	sha1_transform(ctx, ctx->data);

	copyfunc20(hash, (unsigned char*) ctx->state);

}
