//============================================================================
// Name        : sha256.cuh
// Author      : Hannan
// Version     :
// Copyright   : GPL
// Description : Sha256 application
//============================================================================

#ifndef SHA256_H
#define SHA256_H

#include <cstdint>
#include <stdio.h>

#include <cuda.h>
#include <cudart_platform.h>
#include <cuda_runtime.h>
#include <device_launch_parameters.h>


#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest


#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))



typedef unsigned char BYTE;             // 8-bit byte
typedef uint32_t  WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} SHA256_CTX;

__constant__ WORD d_k[64];

static const WORD k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/*********************** FUNCTION DECLARATIONS **********************/

__device__ void sha256_init(SHA256_CTX *ctx);
__device__ void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
__device__ void sha256_final(SHA256_CTX *ctx, BYTE hash[]);

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

__device__ void sha256_transform(SHA256_CTX *ctx, const BYTE data[])
{
	WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	copyinInt((unsigned char*)m, (unsigned char*)data);

	for (i=16; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

#pragma unroll 64
	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e, f, g) + d_k[i] + m[i];
		t2 = EP0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;

}

__device__ void sha256_init(SHA256_CTX *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

__device__ void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len)
{
	int i = 0;
	int OptLen = ctx->datalen + len;

	for (i = 0; i < int(OptLen/64); ++i) {
		memcpy(&ctx->data[ctx->datalen], &data[(i*64)], 64);
		sha256_transform(ctx, ctx->data);
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

__device__ void copyfunc32(unsigned char*a, unsigned char*b){

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

	a[23] = b[20];
	a[22] = b[21];
	a[21] = b[22];
	a[20] = b[23];

	a[27] = b[24];
	a[26] = b[25];
	a[25] = b[26];
	a[24] = b[27];

	a[31] = b[28];
	a[30] = b[29];
	a[29] = b[30];
	a[28] = b[31];


	return;
}

__device__ void sha256_final(SHA256_CTX *ctx, BYTE hash[])
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

		sha256_transform(ctx, ctx->data);

		memset(&ctx->data[0], 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;

	copyfunc8(&ctx->data[56], (unsigned char*)&ctx->bitlen);

	sha256_transform(ctx, ctx->data);


	copyfunc32(hash, (unsigned char*) ctx->state);

}

#endif   // SHA256_H



