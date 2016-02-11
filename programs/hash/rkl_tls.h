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
*                                       Remote Key Loading Cert verification
*********************************************************************************************************
*/

/*
*********************************************************************************************************
*
*                                            RKL Cert verification
*
* Filename      : rkl_tls.h
* Version       : V1.0.0
* Programmer(s) : Manu
*
*********************************************************************************************************
* Note(s)       : Abstraction layer to mbedtls
*
*********************************************************************************************************
*/
#ifndef _RKL_TLS__H_
#define _RKL_TLS__H_


#include "rkl_db.h"
#include <mbedtls/x509_crt.h>
#include "tr34_types.h"
#include "apps_utils.h"
/*
*********************************************************************************************************
*                                    DEFINES
*********************************************************************************************************
*/

#define RKL_RSA_EXPONENT_LEN 3
#define RKL_RSA_KEY_BYTESLEN 256
#define CERT_SUMMARY_MAX_SIZE 1024

/*
*********************************************************************************************************
*                                    DECLARATIONS
*********************************************************************************************************
*/

int RklTls_WriteSessionKeyBlockInClearSequence(unsigned char **p,
											   unsigned char *start,
											   unsigned char *keyHeader,
											   certificate_info_t *certificateInfo,
											   unsigned char *sessionKey);



/**
 * Generate DER for certificate info
 * Note: the buffer is filled from the end. Hence the DER will start at buf + bufSize - *derLen
 * @param[in] buffer buffer to fill
 * @param[in] bufSize original buffer size
 * @param[out] derLen
 * @param[in] certificate info structure to convert to DER
 * @return MBEDTLS error code
 */
int RklTls_GetDerCertificateInfoNamesAndSerial(unsigned char *buf,
											   unsigned short bufSize,
											   unsigned short *derLen,
											   certificate_info_t *certificateInfo);


/**
 * Encrypt with Certificate's Public Key some payload
 */
unsigned int RklTls_CertEncrypt(unsigned char *output, rkms_cert_der_t *cert, unsigned char *input);

unsigned int RklTls_GetDerEncodedKeyPair(unsigned char *buf, unsigned short bufSize, unsigned short *derLen,
										 rsa_key_pair_t *key);

int RklTls_WriteSignedData(unsigned char **p, unsigned char *start, enveloped_data_t *envelopedData);
#endif // _RKL_TLS__H_