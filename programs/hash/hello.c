/*
 * Generate TR34
 */
#include "ProtocolDefinitions.h"
#include "rkl_tls.h"
#include "rkl_tr34.h"
#include "rkl_inject.h"
#include "rkl_db.h"

#if !defined(MBEDTLS_CONFIG_FILE)

#include "mbedtls/config.h"


#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else

#include <stdio.h>
#include <mbedtls/bignum.h>
#include <string.h>
#include <mbedtls/rsa.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/x509_crt.h>

#define mbedtls_printf     printf
#endif

#if defined(MBEDTLS_MD5_C)

#include "mbedtls/md5.h"
#include "apps_utils.h"
#include "rkl_tr34.h"

#endif
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else

#include <stdlib.h>

#define mbedtls_free       free
#define mbedtls_calloc    calloc
#define mbedtls_snprintf   snprintf
#endif


#include <stdio.h>
#include <mbedtls/oid.h>


/*
*********************************************************************************************************
*                                    DEFINES
*********************************************************************************************************
*/


certificate_info_t certificateInfo;
enveloped_data_t envelopedData;


unsigned int calculateEnvevelopedDataDigest(unsigned char digest[256], enveloped_data_t *pData);

unsigned int RklTestTr34_PrintEnvelopedData(enveloped_data_t *envelopedData)
{
	if (NULL == envelopedData)
	{
		POYNT_ERROR("Can't print Enveloped Data. Error %s(0x%x)", RS(REP_STATUS_BAD_PARAMETER));
		return REP_STATUS_BAD_PARAMETER;
	}
	POYNT_LOG(" Enveloped Data:");
	POYNT_LOG(" - Enc. Session Key: %s", Bytes2String(envelopedData->encSessionKey, envelopedData->encSessionKeyLen));
	POYNT_LOG(" - IV: %s", Bytes2String(envelopedData->iv, TR34_SESSION_KEY_IV_LEN));
	POYNT_LOG(" - Enc.EK: %s", Bytes2String(envelopedData->encEphemeralKey, TDES_KEY_BYTES_LENGTH));

	return REP_STATUS_UNSUPPORTED_CMD;
}

int main(void)
{
	unsigned char buf[4096];
	unsigned short len = 0;
	unsigned char encEK[256];
	memset(encEK, 0xAB, 256);

	POYNT_LOG("Test starting..")
	unsigned int r;
	r = RklTr34_GetCertificateInfo(&certificateInfo, "US", "TR34 Samples", "TR34 Sample CA KRD", 2233);
	if (r)
	{
		POYNT_ERROR("Error %s(0x%x)", RS(r));
		return r;
	}

	r = RklTr34_CreateEnvelopeData(&envelopedData,
								   RklInject_GetAndSetNewEphemeralKey(),
								   RklInject_GetAndSetNewSessionKeyIv(),
								   RklTr34_GetSessionKeyHeader(),
								   &certificateInfo,
								   RklInject_GetAndSetNewSessionKey());


	if (r)
	{
		POYNT_ERROR("Error %s(0x%x)", RS(r));
		return r;
	}
	RklTestTr34_PrintEnvelopedData(&envelopedData);

	signed_attributes_t signedAttributes;
	r = RklTr34_CreateSignedAttributes(&signedAttributes,
									   RklInject_GetAndSetNewDeviceNonce(),
									   RklTr34_GetSessionKeyHeader(),
									   &envelopedData);


	if (r)
	{
		POYNT_ERROR("Error %s(0x%x)", RS(r));
		return r;
	}


	PCI_U8(blob, TR34_BLOB_BYTES_MAXLEN);
	unsigned short blobLen = 0;
	r = RklTr34_CreateBlob(blob, &blobLen, &envelopedData, &signedAttributes);
	if (r)
	{
		POYNT_ERROR("Error %s(0x%x)", RS(r));
		return r;
	}
	POYNT_LOG("TR34 Blob (len:%d): %s", blobLen, Bytes2String(blob, blobLen));

	POYNT_DEBUG("DER: (len:%d) %s", blobLen, Bytes2String(blob, blobLen));
	return NO_ERROR;

}

