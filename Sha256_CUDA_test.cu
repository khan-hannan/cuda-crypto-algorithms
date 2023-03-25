//============================================================================
// Name        : Sha256_CUDA_test.cpp
// Author      : Hannan
// Version     :
// Copyright   : GPL
// Description : Sha256 test application
//============================================================================

#include <iostream>

#include "sha256.cuh"


__global__ void Sha256Kernel(const unsigned char* data, int Len, unsigned char* output){
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, data, Len);
	sha256_final(&ctx, output);
}

int main() {

	const char text1[] = {"hello world!"};
	int  text1_Len = strlen(text1);

	int pass = 1;


	cudaMemcpyToSymbol(d_k, k, sizeof(k), 0, cudaMemcpyHostToDevice);

	BYTE hash1[SHA256_BLOCK_SIZE] = {0x75,0x09,0xe5,0xbd,0xa0,0xc7,0x62,0xd2,0xba,0xc7,0xf9,0x0d,0x75,0x8b,0x5b,0x22,
									 0x63,0xfa,0x01,0xcc,0xbc,0x54,0x2a,0xb5,0xe3,0xdf,0x16,0x3b,0xe0,0x8e,0x6c,0xa9};
	BYTE buf[SHA256_BLOCK_SIZE];


	int ArrayOftest = 1;
	unsigned char *d_test;
	unsigned char *d_out;


	cudaMalloc(&d_test, strlen(text1) );
	cudaMalloc(&d_out, SHA256_BLOCK_SIZE);

	cudaMemcpy(d_test, text1, text1_Len, cudaMemcpyHostToDevice);

	Sha256Kernel<<<1,1>>>(d_test, text1_Len, d_out); //task parallel instead of data parallel

	cudaMemcpy(buf, d_out, SHA256_BLOCK_SIZE, cudaMemcpyDeviceToHost);

	pass = pass && !memcmp(hash1, buf, SHA256_BLOCK_SIZE);

	printf("SHA-256 test: %s\n", pass ? "SUCCEEDED" : "FAILED");


	return 0;
}
