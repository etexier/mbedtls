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
 *                                       Remote Key Loading Cert TLS implementation
 *********************************************************************************************************
 */

/*
 *********************************************************************************************************
 *
 *                                            RKL TLS implementation
 *
 * Filename      : rkl_verif.c
 * Version       : V1.0.0
 * Programmer(s) : Manu
 *
 *********************************************************************************************************
 * Note(s)       :
 *
 *********************************************************************************************************
 */

#include "rkl_tls.h"
#include <mbedtls/x509_crt.h>
#include <mbedtls/asn1write.h>
#include "apps_utils.h"
#include <mbedtls/x509_csr.h>
#include <stdio.h>
#include <mbedtls/platform.h>
#include "tr34_types.h"
#include <mbedtls/oid.h>
#include <string.h>
#include "rkl_tr34.h"
#include "ProtocolDefinitions.h"

/*
 *********************************************************************************************************
 *                                            DEFINES
 *********************************************************************************************************
 */
#define ROOT_CN  "Poynt-Root"
#define CERT_VERIFY_ARG    NULL


#ifdef POYNT_PCI_DEBUG
#define CERT_VERIFY_FUNC certVerifyFunc

#else // !POYNT_PCI_DEBUG

#define CERT_VERIFY_FUNC NULL
#define CERT_PRINT_VERIFY_INFO_FUNC(_x_) ((void)(_x_))

#endif

#define KEY_DER_MAX_SIZE 2048
#define CERT_VERIFICATION_FAILURE_INFO(_x_) certVerificationFailureInfo(_x_)

// use https://www.viathinksoft.com/~daniel-marschall/asn.1/oid-converter/online.php OID converter
// '1.2.840.113549.1.1.7'
#define OID_RSAES_OAEP "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x07"
// 1.2.840.113549.1.1.8
#define OID_MGF1 "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x08"
// 1.2.840.113549.1.1.9
#define OID_PSPECIFIED "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x09"

// 1.2.840.113549.1.7.1
#define OID_PKCS7_DATA "\x2A\x86\x48\x86\xF7\x0D\x01\x07\x01"

// 1.2.840.113549.1.7.2
#define OID_PKCS7_SIGNED_DATA "\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02"

// 1.2.840.113549.1.7.3
#define OID_PKCS7_ENVELOPED_DATA "\x2A\x86\x48\x86\xF7\x0D\x01\x07\x03"
#define OID_ADD_LEN(_X_) _X_, sizeof(_X_)-1


/*
 *********************************************************************************************************
 *                                            CONSTANTS
 *********************************************************************************************************
 */

static char *CSR_SUBJECT_TEMPLATE = "C=US,ST=California,L=Palo Alto,O=Poynt Co,OU=Poynt Smart Terminal,CN=%s/emailAddress=terminal-admin@poynt.co";


/*
 *********************************************************************************************************
 *                                            LOCAL FUNCTIONS DECLARATIONS
 *********************************************************************************************************
 */


static int certVerifyFunc(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags);

static void certVerificationFailureInfo(unsigned int flags);

static unsigned int getCertSummary(mbedtls_x509_crt *cert, unsigned char *bufOut, unsigned short *bufLenOut);

static int writeEnvelopedDataInnerSet(unsigned char **p, unsigned char *start, enveloped_data_t *envelopedData);

static int writeEnvelopedDataEkInfo(unsigned char **p, unsigned char *start);

static int writeEncSessionKeySequence(unsigned char **p, unsigned char *start, enveloped_data_t *envelopedData);

static int writeEnvelopedDataOidMgf1(unsigned char **p, unsigned char *start);

static int writeKeyBlockHeaderSequence(unsigned char **p, unsigned char *start, unsigned char *keyHeader);

static int writeEnvelopedData(unsigned char **p, unsigned char *start, enveloped_data_t *envelopedData);

static int writeSignedDataDigestSet(unsigned char **p, unsigned char *start);



/**
 * Write a Certificate info in the current buffer at p, p is automatically updated past the appended value.
 * @param[in/out] pointer to current position, updated past the appended value
 * @param[in] start of buffer for boundaries check
 * @param[in] certificate to add
 */
static int writeCertificateInfo(unsigned char **p, unsigned char *start, certificate_info_t *val);


/*
 *********************************************************************************************************
 *                                            IMPLEMENTATIONS
 *********************************************************************************************************
 */

static void certVerificationFailureInfo(unsigned int flags)
{
	char vrfy_buf[512];
	POYNT_DEBUG("verification failed");
	mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
	POYNT_DEBUG("info : %s", vrfy_buf);
}


static int certVerifyFunc(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
	char buf[1024];
	((void) data);

	POYNT_DEBUG("Verify requested for (Depth %d): ", depth);
	mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "", crt);
	POYNT_DEBUG("%s", buf);

	if ((*flags) == 0)
	{
		POYNT_TRACE("  This certificate has no flags\n");
	}
	else
	{
		mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", *flags);
		POYNT_TRACE("%s", buf);
	}

	return (0);
}

/**
 * @return REP_STATUS_SUCCESS if function was able to dertermine whether the cert is a root cert or not
 */
unsigned int RklTls_VerifyRootCert(rkms_cert_der_t *cert, unsigned int *isRootCert)
{
	ENSURE_POYNT_MBEDTLS_INITIALIZED;

	POYNT_DEBUG("Checking if cert is root cert..");
	unsigned int status;
	unsigned int isRoot = FALSE;
	mbedtls_x509_crt rootCert;
	mbedtls_x509_crt_init(&rootCert);

	int ret = mbedtls_x509_crt_parse_der(&rootCert, cert->der, cert->len);
	if (ret != 0)
	{
		POYNT_ERROR("Failed to parse cert. Error -0x%x", -ret);
		status = REP_STATUS_ERR_FAIL;
		goto isRootCertExit;
	}

	POYNT_DEBUG("Checking if self-signed");
	uint32_t flags;
	if ((mbedtls_x509_crt_verify(&rootCert, // cert to check
								 &rootCert, // trusted ca chain, same as root
								 NULL, // no CERL
								 NULL, // TODO POYNT ROOT CN?
								 &flags,
								 CERT_VERIFY_FUNC, CERT_VERIFY_ARG)) == 0)
	{
		POYNT_DEBUG("Cert is a root");
		isRoot = TRUE;
	}
	else
	{
		POYNT_DEBUG("Cert is not root");
		CERT_VERIFICATION_FAILURE_INFO(flags);
		isRoot = FALSE;
	}
	status = REP_STATUS_SUCCESS;

	isRootCertExit:

	mbedtls_x509_crt_free(&rootCert);
	*isRootCert = isRoot;
	return status;
}

unsigned int RklTls_VerifyNonRootCert(rkms_cert_der_t *cert,
									  rkms_cert_der_t *trustedCerts,
									  unsigned short nTrustedCerts,
									  unsigned int *authenticated)
{
	POYNT_DEBUG("Verifying non-root Cert (len=%d) ", cert->len);

	if (nTrustedCerts == 0)
	{
		POYNT_ERROR("Invalid number of trusted certs: %d", nTrustedCerts);
		return REP_STATUS_BAD_PARAMETER;
	}

	unsigned int status;
	unsigned int isVerified = FALSE;

	ENSURE_POYNT_MBEDTLS_INITIALIZED;

	mbedtls_x509_crt cacert;
	mbedtls_x509_crt_init(&cacert);
	mbedtls_x509_crt clicert;
	mbedtls_x509_crt_init(&clicert);


	// Parse client cert
	int ret = mbedtls_x509_crt_parse_der(&clicert, cert->der, cert->len);
	if (ret)
	{
		POYNT_ERROR("Failed to parse cert. Error -0x%x", -ret);
		status = REP_STATUS_ERR_FAIL;
		goto nonRootCertExit;
	}

	// Parse certs in chain of trust starting from leaf
	int n;
	for (n = nTrustedCerts - 1; n >= 0; n--)
	{
		if (trustedCerts[n].len == 0)
		{
			POYNT_TRACE("No trusted cert at %d, skip", n);
			continue;
		}

		// parse it and add it to the chain
		POYNT_TRACE("parse cert at %d with (len: %d) %s", n, trustedCerts[n].len,
					Bytes2String(trustedCerts[n].der, trustedCerts[n].len));
		ret = mbedtls_x509_crt_parse_der(&cacert, trustedCerts[n].der, trustedCerts[n].len);
		if (ret)
		{
			POYNT_ERROR("Failed to parse trusted cert. Error -0x%x", -ret);
			status = REP_STATUS_ERR_FAIL;
			goto nonRootCertExit;
		}
	}

	// verify non-root cert against current chain of trust

	POYNT_DEBUG("Parse successful. Verifying...");
	uint32_t flags;
	if ((mbedtls_x509_crt_verify(&clicert, // cert to check
								 &cacert, // trusted chain,
								 NULL, // no CRL
								 NULL,
								 &flags,
								 CERT_VERIFY_FUNC, CERT_VERIFY_ARG)) == 0)
	{
		isVerified = TRUE;
	}
	else
	{
		CERT_VERIFICATION_FAILURE_INFO(flags);
	}

	POYNT_DEBUG("Cert Verified? %s", (isVerified ? "TRUE" : "FALSE"));
	status = REP_STATUS_SUCCESS;

	nonRootCertExit:

	mbedtls_x509_crt_free(&cacert);
	mbedtls_x509_crt_free(&clicert);
	*authenticated = isVerified;

	return status;

}

unsigned int RklTls_IsValid(rkms_cert_der_t *rkmsCertDer)
{

	ENSURE_POYNT_MBEDTLS_INITIALIZED;
	int ret;
	mbedtls_x509_crt cert;

	POYNT_TRACE("X.509 certificate init");
	mbedtls_x509_crt_init(&cert);

	POYNT_TRACE("X.509 certificate parse");
	ret = mbedtls_x509_crt_parse(&cert, (const unsigned char *) rkmsCertDer->der, (size_t) rkmsCertDer->len);

	mbedtls_x509_crt_free(&cert);
	if (ret)
	{
		POYNT_ERROR("Failed to parse X.509 certificate");
		return FALSE;
	}
	return TRUE;
}

unsigned int RklTls_GetCertsSummary(rkms_cert_der_t *rkmsCertDer, unsigned short nCerts, unsigned char *bufOut,
									unsigned short *bufLenOut)
{
	ENSURE_POYNT_MBEDTLS_INITIALIZED;
	unsigned int result;
	mbedtls_x509_crt cert;

	POYNT_TRACE("X.509 certificate init");
	mbedtls_x509_crt_init(&cert);

	int i;
	for (i = nCerts - 1; i >= 0; i--)
	{
		rkms_cert_der_t *cur = &rkmsCertDer[i];
		if (cur->len == 0)
		{
			POYNT_DEBUG("No certificates at index #%u", i);
			continue;
		}
		POYNT_DEBUG("X.509 certificate parse certs #%d", i);
		int ret = mbedtls_x509_crt_parse(&cert, (const unsigned char *) cur->der, (size_t) cur->len);
		if (ret)
		{
			POYNT_ERROR("Failed to parse X.509 certificate");
			result = REP_STATUS_ERR_FAIL;
			goto summaryExit;
		}
	}

	POYNT_DEBUG("No failures parsing cert(s)");

	if (getCertSummary(&cert, bufOut, bufLenOut))
	{
		POYNT_ERROR("Couldn't get cert summary");
		result = REP_STATUS_ERR_FAIL;
		goto summaryExit;
	}

	result = REP_STATUS_SUCCESS;

	summaryExit:

	mbedtls_x509_crt_free(&cert);
	return result;

}

unsigned int RklTls_GetCertSummary(rkms_cert_der_t *rkmsCertDer, unsigned char *bufOut, unsigned short *bufLenOut)
{

	return RklTls_GetCertsSummary(rkmsCertDer, 1, bufOut, bufLenOut);
}

static unsigned int getCertSummary(mbedtls_x509_crt *cert, unsigned char *bufOut, unsigned short *bufLenOut)
{
	mbedtls_x509_crt *cur = cert;
	int ret;
	*bufLenOut = 0;
	while (cur != NULL)
	{
		char buf[CERT_SUMMARY_MAX_SIZE];
		PCI_ClearBuffer(buf, FILL_ZEROES, sizeof(buf));
		POYNT_DEBUG("Get Peer certificate information");
		ret = mbedtls_x509_crt_info((char *) buf, sizeof(buf) - 1, "", cur);

		if (ret == -1)
		{
			POYNT_DEBUG("Failed! mbedtls_x509_crt_info");
			return REP_STATUS_ERR_FAIL;
		}

		POYNT_DEBUG("Cert Summary (len:%d) %s", strlen(buf), SubString(buf, strlen(buf)));
		sprintf((char *) (bufOut + (*bufLenOut)), "%s\n\n", buf);
		*bufLenOut = (unsigned short) ((*bufLenOut) + strlen(buf));
		if (*bufLenOut > CERT_SUMMARY_MAX_SIZE)
		{
			*bufLenOut = CERT_SUMMARY_MAX_SIZE;
			break;
		}

		POYNT_DEBUG("Agggregated summary (len: %d): %s", *bufLenOut, SubString((char *) bufOut, *bufLenOut));
		cur = cur->next;
	}

	*bufLenOut = (unsigned short) strlen((const char *) bufOut);
	return REP_STATUS_SUCCESS;

}


int writeKeyPairDer(unsigned char *buf, unsigned short bufSize, unsigned short *derLen, rsa_key_pair_t *key)
{
	int len = 0;
	int ret = 0;

	POYNT_DEBUG("MPI N (%u) %s", key->modulus_length, Bytes2String(key->modulus, key->modulus_length));
	mbedtls_mpi mpiN;
	mbedtls_mpi_init(&mpiN);
	if (mbedtls_mpi_read_binary(&mpiN, key->modulus, key->modulus_length))
	{
		POYNT_ERROR("Couldn't read modulus");
		len = -1;
		goto derExit;

	}

	POYNT_DEBUG("MPI E (%u)", key->public_exponent_length,
				Bytes2String(key->public_exponent, key->public_exponent_length));
	mbedtls_mpi mpiE;
	mbedtls_mpi_init(&mpiE);
	if (mbedtls_mpi_read_binary(&mpiE, key->public_exponent, key->public_exponent_length))
	{
		POYNT_ERROR("Couldn't read public exponent");
		len = -1;
		goto derExit;
	}

	POYNT_DEBUG("MPI D (%u) %s", key->modulus_length, Bytes2String(key->private_exponent, key->modulus_length));
	mbedtls_mpi mpiD;
	mbedtls_mpi_init(&mpiD);
	if (mbedtls_mpi_read_binary(&mpiD, key->private_exponent, key->modulus_length))
	{
		POYNT_ERROR("Couldn't read private exponent");
		len = -1;
		goto derExit;
	}

	POYNT_DEBUG("MPI P (%u) %s", key->modulus_length / 2, Bytes2String(key->prime1, key->modulus_length / 2));
	mbedtls_mpi mpiP;
	mbedtls_mpi_init(&mpiP);
	if (mbedtls_mpi_read_binary(&mpiP, key->prime1, key->modulus_length / 2))
	{
		POYNT_ERROR("Couldn't read prime1");
		len = -1;
		goto derExit;
	}

	POYNT_DEBUG("MPI Q (%u) %s", key->modulus_length / 2, Bytes2String(key->prime2, key->modulus_length / 2));
	mbedtls_mpi mpiQ;
	mbedtls_mpi_init(&mpiQ);
	if (mbedtls_mpi_read_binary(&mpiQ, key->prime2, key->modulus_length / 2))
	{
		POYNT_ERROR("Couldn't read prime2");
		len = -1;
		goto derExit;
	}

	POYNT_DEBUG("MPI DP (%u) %s", key->modulus_length / 2, Bytes2String(key->exponent1, key->modulus_length / 2));
	mbedtls_mpi mpiDP;
	mbedtls_mpi_init(&mpiDP);
	if (mbedtls_mpi_read_binary(&mpiDP, key->exponent1, key->modulus_length / 2))
	{
		POYNT_ERROR("Couldn't read exponent1");
		len = -1;
		goto derExit;

	}

	POYNT_DEBUG("MPI DQ (%u) %s", key->modulus_length / 2, Bytes2String(key->exponent2, key->modulus_length / 2));
	mbedtls_mpi mpiDQ;
	mbedtls_mpi_init(&mpiDQ);
	if (mbedtls_mpi_read_binary(&mpiDQ, key->exponent2, key->modulus_length / 2))
	{
		POYNT_ERROR("Couldn't read exponent2");
		len = -1;
		goto derExit;
	}

	POYNT_DEBUG("MPI QP (%u) %s", key->modulus_length / 2, Bytes2String(key->coefficient, key->modulus_length / 2));
	mbedtls_mpi mpiQP;
	mbedtls_mpi_init(&mpiQP);

	if (mbedtls_mpi_read_binary(&mpiQP, key->coefficient, key->modulus_length / 2))
	{
		POYNT_ERROR("Couldn't read coefficient");
		len = -1;
		goto derExit;
	}

	POYNT_DEBUG("Writing ASN1 PrivateKeyPair DER encoded output");

	unsigned char *c = buf + bufSize;

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&c, buf, &mpiQP));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&c, buf, &mpiDQ));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&c, buf, &mpiDP));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&c, buf, &mpiQ));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&c, buf, &mpiP));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&c, buf, &mpiD));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&c, buf, &mpiE));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&c, buf, &mpiN));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&c, buf, 0));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, (size_t) len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	POYNT_DEBUG("DER ENCODED (len:%u b): %s", len, Bytes2String(c, (unsigned int) len));

	*derLen = (unsigned short) len;

	derExit:

	mbedtls_mpi_free(&mpiN);
	mbedtls_mpi_free(&mpiD);
	mbedtls_mpi_free(&mpiE);
	mbedtls_mpi_free(&mpiP);
	mbedtls_mpi_free(&mpiQ);
	mbedtls_mpi_free(&mpiDP);
	mbedtls_mpi_free(&mpiDQ);
	mbedtls_mpi_free(&mpiQP);

	return len;

}

unsigned int RklTls_GetDerEncodedKeyPair(unsigned char *buf, unsigned short bufSize, unsigned short *derLen,
										 rsa_key_pair_t *key)
{
	if (buf == NULL || bufSize < KEY_DER_MAX_SIZE || derLen == NULL || key == NULL)
	{
		return REP_STATUS_BAD_PARAMETER;
	}

	PCI_ClearBuffer(buf, FILL_ZEROES, bufSize);

	POYNT_DEBUG("Writing Der Buf");

	int r = writeKeyPairDer(buf, bufSize, derLen, key);

	if (r < 0)
	{
		POYNT_ERROR("Writing Private Key DER failed. Error -0x%x", -r);
		return REP_STATUS_BUILDER_ERROR;
	}
	return REP_STATUS_SUCCESS;
}

/*
 *  1137:d=3  hl=4 l= 516 cons:    SET
 *  1141:d=4  hl=4 l= 512 cons:     SEQUENCE
 *  1145:d=5  hl=2 l=   1 prim:      INTEGER           :01
 *  1148:d=5  hl=2 l=  74 cons:      SEQUENCE
 *  1150:d=6  hl=2 l=  65 cons:       SEQUENCE
 *  1152:d=7  hl=2 l=  11 cons:        SET
 *  1154:d=8  hl=2 l=   9 cons:         SEQUENCE
 *  1156:d=9  hl=2 l=   3 prim:          OBJECT            :countryName
 *  1161:d=9  hl=2 l=   2 prim:          PRINTABLESTRING   :US
 *  1165:d=7  hl=2 l=  21 cons:        SET
 *  1167:d=8  hl=2 l=  19 cons:         SEQUENCE
 *  1169:d=9  hl=2 l=   3 prim:          OBJECT            :organizationName
 *  1174:d=9  hl=2 l=  12 prim:          PRINTABLESTRING   :TR34 Samples
 *  1188:d=7  hl=2 l=  27 cons:        SET
 *  1190:d=8  hl=2 l=  25 cons:         SEQUENCE
 *  1192:d=9  hl=2 l=   3 prim:          OBJECT            :commonName
 *  1197:d=9  hl=2 l=  18 prim:          PRINTABLESTRING   :TR34 Sample CA KDH
 *  1217:d=6  hl=2 l=   5 prim:       INTEGER           :3400000006
 *  1224:d=5  hl=2 l=  11 cons:      SEQUENCE
 *  1226:d=6  hl=2 l=   9 prim:       OBJECT            :sha256
 *  1237:d=5  hl=3 l= 142 cons:      cont [ 0 ]
 *  1240:d=6  hl=2 l=  24 cons:       SEQUENCE
 *  1242:d=7  hl=2 l=   9 prim:        OBJECT            :contentType
 *  1253:d=7  hl=2 l=  11 cons:        SET
 *  1255:d=8  hl=2 l=   9 prim:         OBJECT            :pkcs7-envelopedData
 *  1266:d=6  hl=2 l=  32 cons:       SEQUENCE
 *  1268:d=7  hl=2 l=  10 prim:        OBJECT            :1.2.840.113549.1.9.25.3
 *  1280:d=7  hl=2 l=  18 cons:        SET
 *  1282:d=8  hl=2 l=  16 prim:         OCTET STRING
 *       0000 - 16 7e b0 e7 27 81 e4 94-01 12 23 34 45 56 67 78   .~..'.....#4EVgx
 *  1300:d=6  hl=2 l=  31 cons:       SEQUENCE
 *  1302:d=7  hl=2 l=   9 prim:        OBJECT            :pkcs7-data
 *  1313:d=7  hl=2 l=  18 cons:        SET
 *  1315:d=8  hl=2 l=  16 prim:         OCTET STRING      :A0256K0TB00E0000
 *  1333:d=6  hl=2 l=  47 cons:       SEQUENCE
 *  1335:d=7  hl=2 l=   9 prim:        OBJECT            :messageDigest
 *  1346:d=7  hl=2 l=  34 cons:        SET
 *  1348:d=8  hl=2 l=  32 prim:         OCTET STRING
 *       0000 - 5d 98 14 5e 22 fc b7 f6-75 1b 1a 45 3a 30 c5 24   ]..^"...u..E:0.$
 *       0010 - 87 f9 24 bc 75 ef 46 db-79 74 c7 aa 6c 4b c7 2d   ..$.u.F.yt..lK.-
 *  1382:d=5  hl=2 l=  13 cons:      SEQUENCE
 *  1384:d=6  hl=2 l=   9 prim:       OBJECT            :rsaEncryption
 *  1395:d=6  hl=2 l=   0 prim:       NULL
 *  1397:d=5  hl=4 l= 256 prim:      OCTET STRING
 *       0000 - 97 bf ce 9f 17 f1 d3 ba-79 5a bf 24 53 28 0a 3d   ........yZ.$S(.=
 *       0010 - a0 8f f7 9a 28 07 86 04-4c e0 4e fe c6 d4 c1 f5   ....(...L.N.....
 *       0020 - 4f 6f 0e 09 38 22 1a 74-05 ac ce 21 19 1f ac 86   Oo..8".t...!....
 */
static int writeSignedDataSet(unsigned char **p, unsigned char *start, enveloped_data_t *envelopedData)
{
	ENSURE_POYNT_MBEDTLS_INITIALIZED;


	POYNT_DEBUG("Writing Data set..");
	unsigned short len = 0;
	int ret = 0;

	if (*p - start < 1)
	{
		return (MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
	}


	//------------------------

	MBEDTLS_ASN1_CHK_ADD(len, writeCertificateInfo(p, start, envelopedData->certificateInfo)); // version = 1
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(p, start, 1)); // version = 1

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));

	//------------------------
	POYNT_DEBUG("Writing Data set.. DONE len:%d : %s", len, Bytes2String(*p,len));
	return ((int) len);

}

/**
 *    26:d=3  hl=2 l=  13 cons:    SET
 *    28:d=4  hl=2 l=  11 cons:     SEQUENCE
 *    30:d=5  hl=2 l=   9 prim:      OBJECT            :sha256
 */
static int writeSignedDataDigestSet(unsigned char **p, unsigned char *start)
{
	ENSURE_POYNT_MBEDTLS_INITIALIZED;


	POYNT_DEBUG("Writing DER Signed Data Digest Set");

	unsigned short len = 0;
	int ret = 0;

	if (*p - start < 1)
	{
		return (MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
	}


	//------------------------
	MBEDTLS_ASN1_CHK_ADD(len,
						 mbedtls_asn1_write_algorithm_identifier(p, start, OID_ADD_LEN(MBEDTLS_OID_DIGEST_ALG_SHA256),
																 0));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));

	//------------------------

	POYNT_DEBUG("Writing DER Signed Data Digest Set .. DONE len:%d : %s", len, Bytes2String(*p,len));

	return ((int) len);

}

/**
 * Defines the signed data TR34 structure.
 * Ref: X9 TR34-2012 Sec B.9.1 pg 103
 *
 *     0:d=0  hl=4 l=1653 cons: SEQUENCE
 *     4:d=1  hl=2 l=   9 prim:  OBJECT            :pkcs7-signedData
 *    15:d=1  hl=4 l=1638 cons:  cont [ 0 ]
 *    19:d=2  hl=4 l=1634 cons:   SEQUENCE
 *    23:d=3  hl=2 l=   1 prim:    INTEGER           :01
 *    === writeSignedDataDigestSet ===
 *    26:d=3  hl=2 l=  13 cons:    SET
 *    28:d=4  hl=2 l=  11 cons:     SEQUENCE
 *    30:d=5  hl=2 l=   9 prim:      OBJECT            :sha256
 *    === writeEnvelopedData
 *    41:d=3  hl=4 l= 616 cons:    SEQUENCE
 *    45:d=4  hl=2 l=   9 prim:     OBJECT            :pkcs7-envelopedData
 *    56:d=4  hl=4 l= 601 cons:     cont [ 0 ]
 *    60:d=5  hl=4 l= 597 prim:      OCTET STRING
 *    64:d=6       l= 1   prim:        INTEGER: 0
 *    67:d=6       l= xxx cons:        SET:
 *       0000 - 02 01 00 31 82 01 9e 30-82 01 9a 02 01 00 30 4a   ...1...0......0J
 *       0010 - 30 41 31 0b 30 09 06 03-55 04 06 13 02 55 53 31   0A1.0...U....US1
 *       ...
 *   === ommitted - not used by RKMS
 *   661:d=3  hl=4 l= 472 cons:    cont [ 1 ]
 *   ... certificates or crls
 *   === writeSignedDataSet
 *  1137:d=3  hl=4 l= 516 cons:    SET
 *  1141:d=4  hl=4 l= 512 cons:     SEQUENCE
 *  1145:d=5  hl=2 l=   1 prim:      INTEGER           :01
 *  1148:d=5  hl=2 l=  74 cons:      SEQUENCE
 *  1150:d=6  hl=2 l=  65 cons:       SEQUENCE
 *  1152:d=7  hl=2 l=  11 cons:        SET
 *  1154:d=8  hl=2 l=   9 cons:         SEQUENCE
 *  1156:d=9  hl=2 l=   3 prim:          OBJECT            :countryName
 *  1161:d=9  hl=2 l=   2 prim:          PRINTABLESTRING   :US
 *  1165:d=7  hl=2 l=  21 cons:        SET
 *  1167:d=8  hl=2 l=  19 cons:         SEQUENCE
 *  1169:d=9  hl=2 l=   3 prim:          OBJECT            :organizationName
 *  1174:d=9  hl=2 l=  12 prim:          PRINTABLESTRING   :TR34 Samples
 *  1188:d=7  hl=2 l=  27 cons:        SET
 *  1190:d=8  hl=2 l=  25 cons:         SEQUENCE
 *  1192:d=9  hl=2 l=   3 prim:          OBJECT            :commonName
 *  1197:d=9  hl=2 l=  18 prim:          PRINTABLESTRING   :TR34 Sample CA KDH
 *  1217:d=6  hl=2 l=   5 prim:       INTEGER           :3400000006
 *  1224:d=5  hl=2 l=  11 cons:      SEQUENCE
 *  1226:d=6  hl=2 l=   9 prim:       OBJECT            :sha256
 *  1237:d=5  hl=3 l= 142 cons:      cont [ 0 ]
 *  1240:d=6  hl=2 l=  24 cons:       SEQUENCE
 *  1242:d=7  hl=2 l=   9 prim:        OBJECT            :contentType
 *  1253:d=7  hl=2 l=  11 cons:        SET
 *  1255:d=8  hl=2 l=   9 prim:         OBJECT            :pkcs7-envelopedData
 *  1266:d=6  hl=2 l=  32 cons:       SEQUENCE
 *  1268:d=7  hl=2 l=  10 prim:        OBJECT            :1.2.840.113549.1.9.25.3
 *  1280:d=7  hl=2 l=  18 cons:        SET
 *  1282:d=8  hl=2 l=  16 prim:         OCTET STRING
 *       0000 - 16 7e b0 e7 27 81 e4 94-01 12 23 34 45 56 67 78   .~..'.....#4EVgx
 *  1300:d=6  hl=2 l=  31 cons:       SEQUENCE
 *  1302:d=7  hl=2 l=   9 prim:        OBJECT            :pkcs7-data
 *  1313:d=7  hl=2 l=  18 cons:        SET
 *  1315:d=8  hl=2 l=  16 prim:         OCTET STRING      :A0256K0TB00E0000
 *  1333:d=6  hl=2 l=  47 cons:       SEQUENCE
 *  1335:d=7  hl=2 l=   9 prim:        OBJECT            :messageDigest
 *  1346:d=7  hl=2 l=  34 cons:        SET
 *  1348:d=8  hl=2 l=  32 prim:         OCTET STRING
 *       0000 - 5d 98 14 5e 22 fc b7 f6-75 1b 1a 45 3a 30 c5 24   ]..^"...u..E:0.$
 *       0010 - 87 f9 24 bc 75 ef 46 db-79 74 c7 aa 6c 4b c7 2d   ..$.u.F.yt..lK.-
 *  1382:d=5  hl=2 l=  13 cons:      SEQUENCE
 *  1384:d=6  hl=2 l=   9 prim:       OBJECT            :rsaEncryption
 *  1395:d=6  hl=2 l=   0 prim:       NULL
 *  1397:d=5  hl=4 l= 256 prim:      OCTET STRING
 *       0000 - 97 bf ce 9f 17 f1 d3 ba-79 5a bf 24 53 28 0a 3d   ........yZ.$S(.=
 *       0010 - a0 8f f7 9a 28 07 86 04-4c e0 4e fe c6 d4 c1 f5   ....(...L.N.....
 *       0020 - 4f 6f 0e 09 38 22 1a 74-05 ac ce 21 19 1f ac 86   Oo..8".t...!....
 */

int RklTls_WriteSignedData(unsigned char **p, unsigned char *start, enveloped_data_t *envelopedData)
{
	ENSURE_POYNT_MBEDTLS_INITIALIZED;


	POYNT_DEBUG("Writing DER Signed Data..");

	unsigned short len = 0;
	int ret = 0;

	if (*p - start < 1)
	{
		return (MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
	}


	//------------------------

	MBEDTLS_ASN1_CHK_ADD(len, writeSignedDataSet(p, start, envelopedData));
	MBEDTLS_ASN1_CHK_ADD(len, writeEnvelopedData(p, start, envelopedData));
	MBEDTLS_ASN1_CHK_ADD(len, writeSignedDataDigestSet(p, start));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(p, start, 1)); // version = 1


	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0)); // explicit -

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(p, start, OID_ADD_LEN(OID_PKCS7_DATA)));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	//------------------------

	POYNT_DEBUG("Writing DER Signed Data .. DONE len:%d : %s", len, Bytes2String(*p,len));

	return ((int) len);

}

/**
 * B9p101
 * EnvelopedData (inner content):
 * The originatorInfo field is omitted.
 * KeyTransRecipientInfo is chosen for RecipientInfo. IssuerAndSerialNumber is chosen for KeyTransRecipientInfo RecipientIdentifier.
 * The KRD identifier, IDKRDCRED, is included in the RecipientInfos issuerAndSerialNumber field.
 * The keyEncryptionAlgorithm specifies id-RSAES-OAEP : ��1.2.840.113549.1.1.7'. The encryptedKey field contains the encrypting key.
 * The EncryptedContentInfo contentType is id-data.
 * The EncyptedContentInfo contentEncryptionAlgorithm specifies id-tECB :
 * '1.2.840.10047.1.1'.
 * The EncyptedContentInfo encryptedContent field contains the encrypted Key Block BE. The unprotectedAttrs field is omitted.
 *
 *  Defines the structure for the enveloped data structure.
 *  Ref: X9 TR34-2012 Sec B.2.2.3.1 pg 65
 *     0:d=0  hl=4 l= 597 cons: SEQUENCE <-- ommitted
 *     4:d=1  hl=2 l=   1 prim:  INTEGER           :00
 *     7:d=1  hl=4 l= 414 cons:  SET
 *    11:d=2  hl=4 l= 410 cons:   SEQUENCE
 *    15:d=3  hl=2 l=   1 prim:    INTEGER           :00
 *    18:d=3  hl=2 l=  74 cons:    SEQUENCE
 *    20:d=4  hl=2 l=  65 cons:     SEQUENCE
 *    22:d=5  hl=2 l=  11 cons:      SET
 *    24:d=6  hl=2 l=   9 cons:       SEQUENCE
 *    26:d=7  hl=2 l=   3 prim:        OBJECT            :countryName
 *    31:d=7  hl=2 l=   2 prim:        PRINTABLESTRING   :US
 *    35:d=5  hl=2 l=  21 cons:      SET
 *    37:d=6  hl=2 l=  19 cons:       SEQUENCE
 *    39:d=7  hl=2 l=   3 prim:        OBJECT            :organizationName
 *    44:d=7  hl=2 l=  12 prim:        PRINTABLESTRING   :TR34 Samples
 *    58:d=5  hl=2 l=  27 cons:      SET
 *    60:d=6  hl=2 l=  25 cons:       SEQUENCE
 *    62:d=7  hl=2 l=   3 prim:        OBJECT            :commonName
 *    67:d=7  hl=2 l=  18 prim:        PRINTABLESTRING   :TR34 Sample CA KRD
 *    87:d=4  hl=2 l=   5 prim:     INTEGER           :3400000007
 *    94:d=3  hl=2 l=  69 cons:    SEQUENCE
 *    96:d=4  hl=2 l=   9 prim:     OBJECT            :rsaesOaep
 *   107:d=4  hl=2 l=  56 cons:     SEQUENCE
 *   109:d=5  hl=2 l=  13 cons:      SEQUENCE
 *   111:d=6  hl=2 l=   9 prim:       OBJECT            :sha256
 *   122:d=6  hl=2 l=   0 prim:       NULL
 *   124:d=5  hl=2 l=  24 cons:      SEQUENCE
 *   126:d=6  hl=2 l=   9 prim:       OBJECT            :mgf1
 *   137:d=6  hl=2 l=  11 cons:       SEQUENCE
 *   139:d=7  hl=2 l=   9 prim:        OBJECT            :sha256
 *   150:d=5  hl=2 l=  13 cons:      SEQUENCE
 *   152:d=6  hl=2 l=   9 prim:       OBJECT            :pSpecified
 *   163:d=6  hl=2 l=   0 prim:       OCTET STRING
 *   165:d=3  hl=4 l= 256 prim:    OCTET STRING
 *       0000 - 2c bd 08 6d c7 23 28 6d-97 aa 61 7c 1e 94 98 0e   ,..m.#(m..a|....
 *       0010 - 53 9a e8 bf 51 a9 26 c5-5f e4 85 8b e4 80 85 65   S...Q.&._......e
 *       ...
 *   425:d=1  hl=3 l= 173 cons:  SEQUENCE
 *   428:d=2  hl=2 l=   9 prim:   OBJECT            :pkcs7-data
 *   439:d=2  hl=3 l= 159 cons:   SEQUENCE
 *   442:d=3  hl=2 l=   8 prim:    OBJECT            :des-ede3-cbc
 *   452:d=3  hl=2 l=   8 prim:    OCTET STRING
 *       0000 - 01 23 45 67 89 ab cd ef-                          .#Eg.... <-- IV
 *   462:d=3  hl=3 l= 136 prim:    cont [ 0 ]    <--   IMPLICIT Context 0 containing key block
 *       0000 - 2c bd 08 6d c7 23 28 6d-97 aa 61 7c 1e 94 98 0e   ,..m.#(m..a|....
 *       0010 - 53 9a e8 bf 51 a9 26 c5-5f e4 85 8b e4 80 85 65   S...Q.&._......e
 *
 */
static int writeEnvelopedData(unsigned char **p, unsigned char *start, enveloped_data_t *envelopedData)
{

	ENSURE_POYNT_MBEDTLS_INITIALIZED;


	POYNT_DEBUG("Writing DER EnvelopedData DER..");

	unsigned short len = 0;
	int ret = 0;

	if (*p - start < 1)
	{
		return (MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
	}



	//---------------------------

	MBEDTLS_ASN1_CHK_ADD(len, writeEncSessionKeySequence(p, start, envelopedData));

	MBEDTLS_ASN1_CHK_ADD(len, writeEnvelopedDataInnerSet(p, start, envelopedData));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(p, start, 0)); // version = 0


	/*
 *    41:d=3  hl=4 l= 616 cons:    SEQUENCE
 *    45:d=4  hl=2 l=   9 prim:     OBJECT            :pkcs7-envelopedData
 *    56:d=4  hl=4 l= 601 cons:     cont [ 0 ]
 *    60:d=5  hl=4 l= 597 prim:      OCTET STRING

	 */

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_octet_string(p, start, NULL, 0)); // what's above is a inner structure how do we represent it?

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0)); // explicit -

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(p, start, OID_ADD_LEN(OID_PKCS7_ENVELOPED_DATA)));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	//---------------------------
	POYNT_DEBUG("Writing DER EnvelopedData .. DONE len:%d : %s", len, Bytes2String(*p,len));

	return (int) len;
}

/*
 * Certificate info sequence  in an outer Sequence and prepended with version
 *  INTEGER
 *  SEQUENCE
 *
 *    0:d=0  hl=2 l=  42 cons: SEQUENCE
 *    2:d=1  hl=2 l=  11 cons:  SET
 *    4:d=2  hl=2 l=   9 cons:   SEQUENCE
 *    6:d=3  hl=2 l=   3 prim:    OBJECT            :commonName
 *   11:d=3  hl=2 l=   2 prim:    PRINTABLESTRING   :US
 *   15:d=1  hl=2 l=  14 cons:  SET
 *   17:d=2  hl=2 l=  12 cons:   SEQUENCE
 *   19:d=3  hl=2 l=   3 prim:    OBJECT            :surname
 *   24:d=3  hl=2 l=   5 prim:    PRINTABLESTRING   :12345
 *   31:d=1  hl=2 l=  11 cons:  SET
 *   33:d=2  hl=2 l=   9 cons:   SEQUENCE
 *   35:d=3  hl=2 l=   3 prim:    OBJECT            :organizationName
 *   40:d=3  hl=2 l=   2 prim:    PRINTABLESTRING   :US
 */
static int writeCertificateInfo(unsigned char **p, unsigned char *start, certificate_info_t *val)
{

	ENSURE_POYNT_MBEDTLS_INITIALIZED;
	unsigned short len = 0;
	int ret = 0;

	POYNT_DEBUG("Writing Certificate Info..");

	if (*p - start < 1)
	{
		return (MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
	}
	ret = RklTls_GetDerCertificateInfoNamesAndSerial(start, (unsigned short) (*p - start), &len, val);
	if (ret < 0)
	{
		POYNT_ERROR("Couldn't get DER-encoded Certificate Info");
		return ret;
	}
	*p -= len;

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(p, start, val->version)); // version = 0

	POYNT_DEBUG("Writing Certificate Info.. DONE len:%d : %s", len, Bytes2String(*p,len));
	return ((int) len);

}

int RklTls_GetDerCertificateInfoNamesAndSerial(unsigned char *buf,
											   unsigned short bufSize,
											   unsigned short *derLen,
											   certificate_info_t *certificateInfo)
{

	ENSURE_POYNT_MBEDTLS_INITIALIZED;

	if (buf == NULL || derLen == NULL || certificateInfo == NULL)
	{
		return MBEDTLS_ERR_ASN1_INVALID_DATA;
	}


	int ret;
	mbedtls_asn1_named_data *names = NULL;
	mbedtls_x509_name parsed, *parsed_cur, *parsed_prv;
	unsigned char *c;

	PCI_ClearBuffer(&parsed, FILL_ZEROES, sizeof(parsed));
	c = buf + bufSize;
	int r = NO_ERROR;

	char name[sizeof(certificate_info_t)];
	PCI_ClearBuffer(name, FILL_ZEROES, sizeof(name));

	sprintf(name, "C=%s, O=%s, CN=%s", certificateInfo->countryName, certificateInfo->organizationName,
			certificateInfo->commonName);

	POYNT_DEBUG("Certificate Info string is %s", name);
	// Convert comma separated list of names into mbedtls name object list
	ret = mbedtls_x509_string_to_names(&names, name);
	if (ret != 0)
	{
		r = ret;
		goto certInfoExit;
	}

	// Write mbedtls name serial number
	ret = mbedtls_asn1_write_int(&c, buf, certificateInfo->serial); // TODO: serial must be an int. what is this?
	if (ret <= 0)
	{
		r = ret;
		goto certInfoExit;
	}
	// Write mbedtls name object list
	ret += mbedtls_x509_write_names(&c, buf, names);
	if (ret <= 0)
	{
		r = ret;
		goto certInfoExit;
	}

	certInfoExit:
	mbedtls_asn1_free_named_data_list(&names);

	parsed_cur = parsed.next;
	while (parsed_cur != 0)
	{
		parsed_prv = parsed_cur;
		parsed_cur = parsed_cur->next;
		mbedtls_free(parsed_prv);
	}
	if (r)
	{
		*derLen = 0;
	}
	else
	{
		*derLen = (unsigned short) ret;
	}
	return r;
}


unsigned int RklTls_CertEncrypt(unsigned char *output, rkms_cert_der_t *cert, unsigned char *input)
{
	ENSURE_POYNT_MBEDTLS_INITIALIZED;


	unsigned int r = REP_STATUS_SUCCESS;

	mbedtls_x509_crt clicert;
	mbedtls_x509_crt_init(&clicert);


	// Parse RKMS encryption cert
	int ret;

	if ((ret = mbedtls_x509_crt_parse_der(&clicert, cert->der, cert->len)))
	{
		POYNT_ERROR("Failed to parse cert. Error -0x%x", -ret);
		r = REP_STATUS_PARSING_ERROR;
		goto getCertEncKeyExit;
	}


	size_t olen;

	if ((ret = mbedtls_pk_encrypt(&clicert.pk, input, TDES_KEY_BYTES_LENGTH, output, &olen,
								  RKL_RSA_KEY_BYTESLEN, rng_func,
								  NULL)))
	{
		POYNT_ERROR("Failed to parse cert. Error -0x%x", -ret);
		r = REP_STATUS_ENCRYPTION_FAILED;
		goto getCertEncKeyExit;

	}

	getCertEncKeyExit:

	mbedtls_x509_crt_free(&clicert);

	return r;


}

static int writeEnvelopedDataInnerSet(unsigned char **p, unsigned char *start, enveloped_data_t *envelopedData)
{
	ENSURE_POYNT_MBEDTLS_INITIALIZED;
	unsigned short len = 0;
	int ret = 0;

	POYNT_DEBUG("Writing EnvelopedDataInnerSet ..");

	if (*p - start < 1)
	{
		return (MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
	}

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_octet_string(p, start, envelopedData->encEphemeralKey, sizeof(envelopedData->encEphemeralKey)));
	MBEDTLS_ASN1_CHK_ADD(len, writeEnvelopedDataEkInfo(p, start));
	MBEDTLS_ASN1_CHK_ADD(len, writeCertificateInfo(p, start, envelopedData->certificateInfo));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));

	POYNT_DEBUG("Writing EnvelopedDataInnerSet .. DONE len:%d : %s", len, Bytes2String(*p,len));

	return (int) len;

}

/**
 *    94:d=3  hl=2 l=  69 cons:    SEQUENCE
 *    96:d=4  hl=2 l=   9 prim:     OBJECT            :1.2.840.113549.1.1.7
 *   107:d=4  hl=2 l=  56 cons:     SEQUENCE
 *   109:d=5  hl=2 l=  13 cons:      SEQUENCE
 *   111:d=6  hl=2 l=   9 prim:       OBJECT            :sha256
 *   122:d=6  hl=2 l=   0 prim:       NULL
 *   124:d=5  hl=2 l=  24 cons:      SEQUENCE
 *   126:d=6  hl=2 l=   9 prim:       OBJECT            :1.2.840.113549.1.1.8
 *   137:d=6  hl=2 l=  11 cons:       SEQUENCE
 *   139:d=7  hl=2 l=   9 prim:        OBJECT            :sha256
 *   150:d=5  hl=2 l=  13 cons:      SEQUENCE
 *   152:d=6  hl=2 l=   9 prim:       OBJECT            :1.2.840.113549.1.1.9
 *   163:d=6  hl=2 l=   0 prim:       OCTET STRING
 */

static int writeEnvelopedDataEkInfo(unsigned char **p, unsigned char *start)
{
	ENSURE_POYNT_MBEDTLS_INITIALIZED;
	unsigned short len = 0;
	int ret = 0;

	POYNT_DEBUG("Writing EnvelopedDataEkInfo ..");

	if (*p - start < 1)
	{
		return (MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
	}
	// Optional Label default is null string
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_octet_string(p, start, NULL, 0));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(p, start, OID_ADD_LEN(OID_PSPECIFIED)));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));


	MBEDTLS_ASN1_CHK_ADD(len, writeEnvelopedDataOidMgf1(p, start));

	MBEDTLS_ASN1_CHK_ADD(len,
						 mbedtls_asn1_write_algorithm_identifier(p, start, OID_ADD_LEN(MBEDTLS_OID_DIGEST_ALG_SHA256),
																 0));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(p, start, OID_ADD_LEN(OID_RSAES_OAEP)));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));


	POYNT_DEBUG("Writing EnvelopedDataEkInfo.. DONE len:%d : %s", len, Bytes2String(*p,len));

	return ((int) len);

}

/*
 * Add session key block (with encrypted key)
 * Session Key Sequence, contains the Encrypted Session key (encrypted with the Ephemeral Key and the IV )
 * 425:d=1  hl=3 l= 173 cons:  SEQUENCE
 * 428:d=2  hl=2 l=   9 prim:   OBJECT            :pkcs7-data
 * 439:d=2  hl=3 l= 159 cons:   SEQUENCE
 * 442:d=3  hl=2 l=   8 prim:    OBJECT            :des-ede3-cbc
 * 452:d=3  hl=2 l=   8 prim:    OCTET STRING
 * 0000 - 01 23 45 67 89 ab cd ef-                          .#Eg.... 						<-- IV
 * 462:d=3  hl=3 l= 136 prim:    cont [ 0 ]       											<- Encrypted session Key
 */
static int writeEncSessionKeySequence(unsigned char **p, unsigned char *start, enveloped_data_t *envelopedData)
{
	ENSURE_POYNT_MBEDTLS_INITIALIZED;
	unsigned short len = 0;
	int ret = 0;

	POYNT_DEBUG("Writing EncSessionKeySequence ..");

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_octet_string(p, start, envelopedData->encSessionKey,
															  envelopedData->encSessionKeyLen));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_octet_string(p, start, envelopedData->iv, TR34_SESSION_KEY_IV_LEN));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(p, start, OID_ADD_LEN(MBEDTLS_OID_DES_EDE3_CBC)));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(p, start, OID_ADD_LEN(OID_PKCS7_DATA)));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	if (*p - start < 1)
	{
		return (MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
	}
	POYNT_DEBUG("Writing EncSessionKeySequence.. DONE len:%d : %s", len, Bytes2String(*p,len));

	return (int) len;
}

static int writeEnvelopedDataOidMgf1(unsigned char **p, unsigned char *start)
{
	ENSURE_POYNT_MBEDTLS_INITIALIZED;
	unsigned short len = 0;
	int ret = 0;

	POYNT_DEBUG("Writing EnvelopedDataOidMgf1 ..");

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(p, start, OID_ADD_LEN(MBEDTLS_OID_DIGEST_ALG_SHA256)));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(p, start, OID_ADD_LEN(OID_MGF1)));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	POYNT_DEBUG("Writing EnvelopedDataOidMgf1.. DONE len:%d : %s", len, Bytes2String(*p,len));

	return len;

}

/**
 * Example:
 *    === START Key Block Header ==
 *   100:d=1  hl=2 l=  31 cons:  SEQUENCE
 *   102:d=2  hl=2 l=   9 prim:   OBJECT            :pkcs7-data ('1.2.840.113549.1.7.1)
 *   113:d=2  hl=2 l=  18 cons:   SET
 *   115:d=3  hl=2 l=  16 prim:    OCTET STRING      :A0256K0TB00E0000
 *    === END Key Block Header ==
 */
static int writeKeyBlockHeaderSequence(unsigned char **p, unsigned char *start, unsigned char *keyHeader)
{
	ENSURE_POYNT_MBEDTLS_INITIALIZED;


	unsigned short len = 0;
	int ret = 0;

	POYNT_DEBUG("Writing KeyBlockHeaderSequence ..");

	if (*p - start < 1)
	{
		return (MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
	}

	//------------------------

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_octet_string(p, start, keyHeader, TR34_SESSION_KEY_BLOCK_LEN));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(p, start, OID_ADD_LEN(OID_PKCS7_DATA)));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	//------------------------

	POYNT_DEBUG("Writing KeyBlockHeaderSequence.. DONE len:%d : %s", len, Bytes2String(*p,len));

	return ((int) len);

}


/*
 * Un-encrypted Key block contains a version, certificate info , key and keyblock-header
 * Example:
 *     0:d=0  hl=3 l= 130 cons: SEQUENCE
 *
 *     == START VERSION ===
 *     3:d=1  hl=2 l=   1 prim:  INTEGER           :01
 *     == END VERSION ===
 *
 *     == START CERTIFICATION INFO ===
 *     6:d=1  hl=2 l=  74 cons:  SEQUENCE
 *     8:d=2  hl=2 l=  65 cons:   SEQUENCE
 *    10:d=3  hl=2 l=  11 cons:    SET
 *    12:d=4  hl=2 l=   9 cons:     SEQUENCE
 *    14:d=5  hl=2 l=   3 prim:      OBJECT            :countryName
 *    19:d=5  hl=2 l=   2 prim:      PRINTABLESTRING   :US
 *    23:d=3  hl=2 l=  21 cons:    SET
 *    25:d=4  hl=2 l=  19 cons:     SEQUENCE
 *    27:d=5  hl=2 l=   3 prim:      OBJECT            :organizationName
 *    32:d=5  hl=2 l=  12 prim:      PRINTABLESTRING   :TR34 Samples
 *    46:d=3  hl=2 l=  27 cons:    SET
 *    48:d=4  hl=2 l=  25 cons:     SEQUENCE
 *    50:d=5  hl=2 l=   3 prim:      OBJECT            :commonName
 *    55:d=5  hl=2 l=  18 prim:      PRINTABLESTRING   :TR34 Sample CA KDH
 *    75:d=2  hl=2 l=   5 prim:   INTEGER           :3400000006
 *    === END certificate info ==
 *
 *    === START Session Key in Clear ==
 *    82:d=1  hl=2 l=  16 prim:  OCTET STRING
 *       0000 - 01 23 45 67 89 ab cd ef-fe dc ba 98 76 54 32 10   .#Eg........vT2.
 *    === END Session Key  ==
 *
 *    === START Key Block Header ==
 *   100:d=1  hl=2 l=  31 cons:  SEQUENCE
 *   102:d=2  hl=2 l=   9 prim:   OBJECT            :pkcs7-data ('1.2.840.113549.1.7.1')
 *   113:d=2  hl=2 l=  18 cons:   SET
 *   115:d=3  hl=2 l=  16 prim:    OCTET STRING      :A0256K0TB00E0000
 *    === END Key Block Header ==
 *
 */
int RklTls_WriteSessionKeyBlockInClearSequence(unsigned char **p,
											   unsigned char *start,
											   unsigned char *keyHeader,
											   certificate_info_t *certificateInfo,
											   unsigned char *sessionKey)
{
	ENSURE_POYNT_MBEDTLS_INITIALIZED;


	unsigned short len = 0;
	int ret = 0;

	POYNT_DEBUG("Writing SessionKeyBlockInClearSequence ..");

	if (*p - start < 1)
	{
		return (MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
	}

	//------------------------

	MBEDTLS_ASN1_CHK_ADD(len, writeKeyBlockHeaderSequence(p, start, keyHeader));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_octet_string(p, start, sessionKey, TDES_KEY_BYTES_LENGTH));
	MBEDTLS_ASN1_CHK_ADD(len, writeCertificateInfo(p, start, certificateInfo));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(p, start, 1)); // always 1

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
															   MBEDTLS_ASN1_SEQUENCE));

	//------------------------

	POYNT_DEBUG("Writing SessionKeyBlockInClearSequence.. DONE len:%d : %s", len, Bytes2String(*p,len));

	return ((int) len);

}
