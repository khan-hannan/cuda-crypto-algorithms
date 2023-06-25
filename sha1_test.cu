/*
 * sha1_test.cpp
 *
 *  Created on: Jun 25, 2023
 *      Author: khan
 */


#include <stdio.h>
#include <memory.h>
#include <string.h>
#include "sha1.cuh"

/*********************** FUNCTION DEFINITIONS ***********************/

__global__ void Sha256Kernel(const unsigned char* data, int Len, unsigned char* output){
	SHA1_CTX ctx;
	sha1_init(&ctx);
	sha1_update(&ctx, data, Len);
	sha1_final(&ctx, output);
}

int main()
{
	const char text1[] = {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
	int  text1_Len = strlen(text1);

	int pass = 1;


	BYTE hash1[SHA1_BLOCK_SIZE] = {0x84,0x98,0x3e,0x44,0x1c,0x3b,0xd2,0x6e,0xba,0xae,0x4a,0xa1,0xf9,0x51,0x29,0xe5,0xe5,0x46,0x70,0xf1};
	BYTE buf[SHA1_BLOCK_SIZE];


	int ArrayOftest = 1;
	unsigned char *d_test;
	unsigned char *d_out;


	cudaMalloc(&d_test, strlen(text1) );
	cudaMalloc(&d_out, SHA1_BLOCK_SIZE);

	cudaMemcpy(d_test, text1, text1_Len, cudaMemcpyHostToDevice);

	Sha256Kernel<<<1,1>>>(d_test, text1_Len, d_out); //task parallel instead of data parallel

	cudaMemcpy(buf, d_out, SHA1_BLOCK_SIZE, cudaMemcpyDeviceToHost);

	pass = pass && !memcmp(hash1, buf, SHA1_BLOCK_SIZE);

	printf("SHA-1 test: %s\n", pass ? "SUCCEEDED" : "FAILED");

	return(0);
}

