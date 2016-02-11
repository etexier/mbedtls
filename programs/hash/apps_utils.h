//
// Created by Emmanuel Texier on 2/10/16.
//

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#ifndef MBED_TLS_APPS_UTILS_H
#define MBED_TLS_APPS_UTILS_H

#define PCI_U8(b,s) \
	unsigned char b[s]; \
	PCI_ClearBuffer(b, FILL_ZEROES, s-0);

#define PCI_U8_CLEAR(b) PCI_ClearBuffer(b, FILL_ZEROES, sizeof(b)-0)


/*
*********************************************************************************************************
*                                    TYPES
*********************************************************************************************************
*/
typedef enum
{
	FILL_ZEROES = 0x00,
	FILL_FF = 0x01,
	FILL_RANDOM = 0x02
} filltype;

#define POYNT_DEBUG(fmt, ...)    printf("[D] "fmt, ##__VA_ARGS__);printf("\n");
#define POYNT_ERROR(fmt, ...)    printf("[E] "fmt, ##__VA_ARGS__);printf("\n");
#define POYNT_TRACE(fmt, ...)    printf("[E] "fmt, ##__VA_ARGS__);printf("\n");
#define POYNT_LOG(fmt, ...)    printf("[E] "fmt, ##__VA_ARGS__);printf("\n");

#define POYNT_WARN(fmt, ...)    printf("[E] "fmt, ##__VA_ARGS__);printf("\n");
char *Bytes2String(unsigned char *bytes, unsigned int len);
unsigned int PCI_ClearBuffer(void *p_buffer, char filltype, unsigned int buffer_length);
int rng_func(void *unused, unsigned char *r, size_t rand_byteLen);

char *SubString(char *string, unsigned int len);
int An2Bytes(char *alphanumerics, unsigned char *bytes, unsigned int anLen);


#define RKL_RSA_KEY_BYTESLEN    256
#define POYNT_RSA_KEY_BYTES_MAXLEN 256

typedef unsigned char u8;
typedef unsigned int u32;


typedef struct
{
	/** The modulus @p n. */
	u8 modulus[POYNT_RSA_KEY_BYTES_MAXLEN];
	/** The modulus byte length. */
	u32 modulus_length;
	/** The private exponent @p d. */
	u8 private_exponent[POYNT_RSA_KEY_BYTES_MAXLEN];

	/** @f$ d_p = d \bmod (p-1) @f$. */
	u8 exponent1[POYNT_RSA_KEY_BYTES_MAXLEN / 2];

	/** @f$ d_q = d \bmod (q-1) @f$. */
	u8 exponent2[POYNT_RSA_KEY_BYTES_MAXLEN / 2];

	/** @a p. */
	u8 prime1[POYNT_RSA_KEY_BYTES_MAXLEN / 2];
	/** @a q. */
	u8 prime2[POYNT_RSA_KEY_BYTES_MAXLEN / 2];
	/** @f$ q^{-1} \bmod p @f$ */
	u8 coefficient[POYNT_RSA_KEY_BYTES_MAXLEN / 2];

	/** The public exponent @p e. */
	u8 public_exponent[3];
	/** The public exponent byte length. */
	u32 public_exponent_length;
} rsa_key_pair_t;
char *Poynt_ToRepStatusName(int actual);

int isZeroized(unsigned char *p, int len);

int Encrypt3DesCbc(unsigned char *dataOut, unsigned char *dataIn, unsigned char *key, unsigned char *IV,
				   unsigned int data_byteLen);

/**
 * Append PkCS5 padding to a data buffer
 */
void ApplyPKCS5Padding(unsigned char *data, unsigned short dataLen, unsigned short *paddedDataLen);


#endif //MBED_TLS_APPS_UTILS_H

