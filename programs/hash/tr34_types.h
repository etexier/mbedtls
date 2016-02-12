/*============================================================================
 *
 * Copyright (c) 2014-2016 POYNT CO.
 * All Rights Reserved.
 *
 * This software is  the  confidential and proprietary  information of Poynt Co.
 * ("Confidential  Information"). You  shall  not disclose  such  Confidential
 * Information  and  shall  use  it only in  accordance with the terms of the
 * license agreement you entered into with Poynt.
 *
 * Poynt Co. makes no representations  or warranties about  the  suitability of
 * the software, either  express  or  implied, including  but  not  limited to
 * the implied warranties of merchantability, fitness for a particular purpose
 * or non-infringement. Poynt Co. shall not  be liable for any damages suffered
 * by licensee as the result of using, modifying or distributing this software
 * or its derivatives.
 *
 *==========================================================================*/
/*
*********************************************************************************************************
*                                       TR-34 types
*********************************************************************************************************
*/

/*
*********************************************************************************************************
*
*                                            TR-34 types
*
* Filename      : tr34_types.h
* Version       : V1.0.0
* Programmer(s) : Manu
*
*********************************************************************************************************
* Note(s)       :
*
*********************************************************************************************************
*/

#ifndef _TR34_TYPES_H_
#define _TR34_TYPES_H_


/*
*********************************************************************************************************
*                                    DEFINES
*********************************************************************************************************
*/

#define TR34_SESSION_KEY_BLOCK_LEN 16
#define TR34_SESSION_KEY_IV_LEN 8
#define TR34_MAX_SESSION_KEY_BLOCK_LEN 1024
#define TR34_BLOB_BYTES_MAXLEN 2048
#define TR34_PUB_KEY_ENC_DATA_LEN 256
#define TR34_DIGEST_LEN 32

#define TDES_KEY_BYTES_LENGTH 24


/*
*********************************************************************************************************
*                                    TYPES
*********************************************************************************************************
*/

/////////////////////////////////////////////////////////////////////////////////////////////////////////
// Certificate Info
/////////////////////////////////////////////////////////////////////////////////////////////////////////

// X9 TR-34 spec B.2.2.1.1.1 p56
typedef struct certificate_info // issuer and serial number
{
	char countryName[32+1];
	char organizationName[256+1];
	char commonName[32+1];
	unsigned int serial; // todo , what is this?


} certificate_info_t;

/////////////////////////////////////////////////////////////////////////////////////////////////////////
// TR34 Key block
/////////////////////////////////////////////////////////////////////////////////////////////////////////

// X9 TR-34 spec B.2.2.2.1
typedef struct tr34_key_block
{
	certificate_info_t *certificateInfo;
	unsigned char key[TDES_KEY_BYTES_LENGTH];
	unsigned char iv[TR34_SESSION_KEY_IV_LEN];
	char header[TR34_SESSION_KEY_BLOCK_LEN]; // hardcoded
} tr34_key_block_t;

/////////////////////////////////////////////////////////////////////////////////////////////////////////
// Envelope data
/////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Defines the structure for the enveloped data structure.
 * Ref: X9 TR34-2012 Sec B.2.2.3.1 pg 65
 */
typedef struct envelope_data
{
	certificate_info_t *certificateInfo;
	unsigned char encEphemeralKey[TR34_PUB_KEY_ENC_DATA_LEN];
	unsigned char encSessionKey[TR34_MAX_SESSION_KEY_BLOCK_LEN];
	unsigned short encSessionKeyLen;
	unsigned char *iv;
} enveloped_data_t;


/////////////////////////////////////////////////////////////////////////////////////////////////////////
// Signed Attributes
/////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct signed_attributes
{
	char *nonce; // nonce in ASCII
	unsigned char header[TR34_SESSION_KEY_BLOCK_LEN];
	unsigned char digest[TR34_DIGEST_LEN]; // SHA256 digest of envelope data
	unsigned char signature[TR34_PUB_KEY_ENC_DATA_LEN]; // signature of attributes signed with 2048bits pubkey

} signed_attributes_t;




#endif // _TR34_TYPES_H