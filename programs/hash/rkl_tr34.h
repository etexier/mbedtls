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
*                                       TR-34 Functions Header
*********************************************************************************************************
*/

/*
*********************************************************************************************************
*
*                                            TR-34 Functions
*
* Filename      : rkl_tr34.h
* Version       : V1.0.0
* Programmer(s) : Manu
*
*********************************************************************************************************
* Note(s)       :
*
*********************************************************************************************************
*/
#include "tr34_types.h"
#include "rkl_db.h"

#ifndef _RKL_TR34_H_
#define _RKL_TR34_H_

/*
*********************************************************************************************************
*                                    DEFINES
*********************************************************************************************************
*/

/*
*********************************************************************************************************
*                                    TYPES
*********************************************************************************************************
*/

/*
*********************************************************************************************************
*                                    DECLARATIONS
*********************************************************************************************************
*/

unsigned char *RklTr34_GetSessionKeyHeader();


unsigned int RklTr34_GetCertificateInfo(certificate_info_t *info, char *c, char *o, char *cn, unsigned int serial);


unsigned int RklTr34_CreateEnvelopeData(enveloped_data_t *envelopedData,
										unsigned char *ephemeralKey,
										unsigned char *iv,
										unsigned char *keyHeader,
										certificate_info_t *certificateInfo,
										unsigned char *sessionKey);

/**
 * Create TR34 blob. Assembles the enveloped data, key block,
 * and signed attributes structures then combines them into the signed data structure.
 */
unsigned int RklTr34_CreateBlob(unsigned char *blob, unsigned short *blobLen, enveloped_data_t *envelopedData);

unsigned int RklTr34_GetEncEphemeralKey(unsigned char *encEK);


#endif // _RKL_TR34_H_