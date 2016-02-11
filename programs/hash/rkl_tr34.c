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
*                                       TR-34 Functions implementation
*********************************************************************************************************
*/

/*
*********************************************************************************************************
*
*                                            TR-34 Functions
*
* Filename      : rkl_tr34.c
* Version       : V1.0.0
* Programmer(s) : Manu
*
*********************************************************************************************************
* Note(s)       :
*
*********************************************************************************************************
*/


#include "ProtocolDefinitions.h"
#include "apps_utils.h"
#include "rkl_db.h"
#include "rkl_tls.h"
#include "apps_utils.h"


/*
*********************************************************************************************************
*                                    DEFINES
*********************************************************************************************************
*/

/*
*********************************************************************************************************
*                                    CONSTANTS
*********************************************************************************************************
*/

// B0096K0TB00E0000
// As described in X9 TR 31 2010 specification p12
unsigned char tr34_session_key_block_header[TR34_SESSION_KEY_BLOCK_LEN] = {
		'B', // block version using Key block Binding method defined in paragraph 5.3.2.1 p 5
		'0', '0', '9', '6',
		'K', '0', // Key Usage - key encryption or wrapping
		'T', // Algorithm - TDES
		'B', // Mode of Use - Both Encrypt and Decrypt / Wrap & Unwrap
		'0', '0', // Key version number - 0
		'E', // Exportability - Exportable
		'0', '0', // Optional Blocks number - none 0x3030
		'0', '0', // RFU = 0x3030
};


/*
*********************************************************************************************************
*                                    DECLARATIONS
*********************************************************************************************************
*/

/**
 * Create an encrypted key block structure
 */
static unsigned int createEncryptedKeyBlock(unsigned char *outBuf,
											unsigned short *outBufLen,
											unsigned char *ephemeralKey,
											unsigned char *iv,
											unsigned char *keyHeader,
											certificate_info_t *certificateInfo,
											unsigned char *sessionKey);


unsigned char *RklTr34_GetSessionKeyHeader()
{
	return tr34_session_key_block_header;
}

unsigned int RklTr34_GetEncEphemeralKey(unsigned char *encEK)
{
	unsigned char *key = RklTr34_GetRkiEphemeralKey();

	// Check if Key is set. Ephemeral Key is a TDES key
	if (isZeroized(key, TDES_KEY_BYTES_LENGTH))
	{
		POYNT_ERROR("Couldn't encrypt. Ephemeral Key not generated");
		return REP_STATUS_ENCRYPTION_KEY_NOT_FOUND;
	}

	unsigned int r;
	rkms_cert_der_t cert;
	if ((r = RklDb_GetWorkingRkmsEncryptionCert(&cert)))
	{
		return r;
	}

	if ((r = RklTls_CertEncrypt(encEK, &cert, key)))
	{
		return r;
	}

	POYNT_DEBUG("Encrypted EK with RKMS Signing cert (len:%d): %s", Bytes2String(encEK, RKL_RSA_KEY_BYTESLEN));
	return REP_STATUS_SUCCESS;
}

// see Py createEncryptedKeyBlock to create encrypted key block cipher
// the key block cipher is built in KeyBlock.py
// an example here: X9 TR34-2012 Sec B.2.2.2.1 pg 63
static unsigned int createEncryptedKeyBlock(unsigned char *outBuf,
											unsigned short *outBufLen,
											unsigned char *ephemeralKey,
											unsigned char *iv,
											unsigned char *keyHeader,
											certificate_info_t *certificateInfo,
											unsigned char *sessionKey)
{

	PCI_U8(start, TR34_MAX_SESSION_KEY_BLOCK_LEN);

	unsigned char *end = start + sizeof(start) - 8; // Keep enough for padding
	unsigned char *p = end;
	int len = 0;

	// Get session key sequence in clear
	if ((len = RklTls_WriteSessionKeyBlockInClearSequence(&p, start, keyHeader, certificateInfo, sessionKey)) < 0)
	{
		POYNT_ERROR("Couldn't create Session Key Block DER. Error -0x%x", -len);
		return REP_STATUS_BUILDER_ERROR;
	}


	// Padding
	unsigned char *inBuf = end - len;

	POYNT_DEBUG("Clear Session Key Block w/o padding (len:%d): %s", len, Bytes2String(inBuf, len));

	unsigned short padLen = 0;
	ApplyPKCS5Padding(inBuf, (unsigned short) len, &padLen);

	POYNT_DEBUG("Clear Session Key Block WITH padding (len:%d): %s", len+padLen, Bytes2String(inBuf, len+padLen));

	// Encryption
	if (Encrypt3DesCbc(outBuf, inBuf, ephemeralKey, iv, (unsigned int) (len + padLen)))
	{
		POYNT_ERROR("Couldn't Encrypt Key Block Sequence");
		return REP_STATUS_ENCRYPTION_FAILED;
	}

	*outBufLen = (unsigned short) (len + padLen);
	memcpy(outBuf, inBuf, *outBufLen);
	PCI_U8_CLEAR(start);

	POYNT_DEBUG("Enc. Session Key Block (len:%d): %s", *outBufLen, Bytes2String(outBuf, *outBufLen));
	return REP_STATUS_SUCCESS;
}

unsigned int RklTr34_GetCertificateInfo(certificate_info_t *info, char *c, char *o, char *cn, unsigned int serial)
{
	if (info == NULL ||
		strlen(cn) >= sizeof(info->commonName) ||
		strlen(c) >= sizeof(info->countryName) ||
		strlen(o) >= sizeof(info->organizationName))
	{
		unsigned int r = REP_STATUS_BAD_PARAMETER;
		POYNT_ERROR("Certificate info params invalid. Error %s(0x%s)", RS(r));
		return r;
	}

	PCI_U8_CLEAR(info->commonName); // PCI safety and also ensure string is NULL terminated
	memcpy(info->commonName, cn, strlen(cn));

	PCI_U8_CLEAR(info->countryName);
	memcpy(info->countryName, c, strlen(c));

	PCI_U8_CLEAR(info->organizationName);
	memcpy(info->organizationName, o, strlen(o));

	info->version = 0;
	info->serial = serial;

	return REP_STATUS_SUCCESS;
}

unsigned int RklTr34_CreateEnvelopeData(enveloped_data_t *envelopedData,
										unsigned char *ephemeralKey,
										unsigned char *iv,
										unsigned char *keyHeader,
										certificate_info_t *certificateInfo,
										unsigned char *sessionKey)

{

	if (envelopedData == NULL || ephemeralKey == NULL || sessionKey == NULL || iv == NULL || keyHeader == NULL ||
		certificateInfo == NULL ||
		isZeroized(ephemeralKey, TDES_KEY_BYTES_LENGTH) || isZeroized(sessionKey, TDES_KEY_BYTES_LENGTH))
	{
		POYNT_ERROR("Couldn't create Enveloped Data. Invalid parameters.");
		return REP_STATUS_BAD_PARAMETER;
	}

	POYNT_DEBUG("Generating TR34 Blob...");
	POYNT_DEBUG(" - IV: %s", Bytes2String(iv, TR34_SESSION_KEY_IV_LEN));
	POYNT_DEBUG(" - EK: %s", Bytes2String(ephemeralKey, TDES_KEY_BYTES_LENGTH));
	POYNT_DEBUG(" - Session Key: %s", Bytes2String(sessionKey, TDES_KEY_BYTES_LENGTH));
	POYNT_DEBUG(" - Block Header: %s", SubString(keyHeader, TR34_SESSION_KEY_BLOCK_LEN));

	envelopedData->certificateInfo = certificateInfo;
	envelopedData->iv =  iv; // WARNING this is NOT copied, as IV is somehow sensitive data.

	unsigned int r;
	if ((r = createEncryptedKeyBlock(envelopedData->encSessionKey, &(envelopedData->encSessionKeyLen),
									 ephemeralKey, iv, keyHeader, certificateInfo, sessionKey)))
	{
		POYNT_ERROR("Couldn't create Encrypted Key Session Block. %s(0x%x)", RS(r));
		return r;
	}

	return REP_STATUS_SUCCESS;
}

unsigned int RklTr34_CreateBlob(unsigned char *blob, unsigned short *blobLen, enveloped_data_t *envelopedData)
{

	if (blob == NULL || envelopedData == NULL || blobLen == NULL)
	{
		POYNT_ERROR("Couldn't create TR34 Blob. Invalid parameters.");
		return REP_STATUS_BAD_PARAMETER;
	}

	PCI_U8(buf, TR34_BLOB_BYTES_MAXLEN);

	unsigned char *p = buf + sizeof(buf); // it's only

	POYNT_DEBUG("Generating TR34 Blob...");

	int len = RklTls_WriteSignedData(&p, buf, envelopedData);

	if (len < 0)
	{
		POYNT_ERROR("Writing TR34 Blob failed. Error -0x%x", -len);
		return REP_STATUS_BUILDER_ERROR;
	}

	memcpy(blob, *p, len);
	*blobLen = (unsigned short) len;

	return REP_STATUS_SUCCESS;

}


