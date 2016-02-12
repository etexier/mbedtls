//
// Created by Emmanuel Texier on 2/10/16.
//
#include "rkl_inject.h"
#include "apps_utils.h"
#include "ProtocolDefinitions.h"
#include "tr34_types.h"

unsigned char rki_session_key[TDES_KEY_BYTES_LENGTH] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
														0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
unsigned char rki_ek[TDES_KEY_BYTES_LENGTH] = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98,
											   0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
char *device_nonce = "12345678";
unsigned char rki_iv[TR34_SESSION_KEY_IV_LEN] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};


unsigned char *RklInject_GetAndSetNewSessionKey()
{
	unsigned char *p = rki_session_key;
//	PCI_ClearBuffer(p, FILL_RANDOM, TDES_KEY_BYTES_LENGTH);
	POYNT_DEBUG("Generated Rki Session Key: %s", Bytes2String(p, TDES_KEY_BYTES_LENGTH));
	return p;
}

char *RklInject_GetAndSetNewDeviceNonce()
{
	char *p = device_nonce;
//	POYNT_DEBUG("Generated Rki Ephemeral Key: %s", Bytes2String(p, TDES_KEY_BYTES_LENGTH));
	return p;
}

unsigned char *RklInject_GetAndSetNewEphemeralKey()
{
	unsigned char *p = rki_ek;
//	PCI_ClearBuffer(p, FILL_RANDOM, TDES_KEY_BYTES_LENGTH);
	POYNT_DEBUG("Generated Rki Ephemeral Key: %s", Bytes2String(p, TDES_KEY_BYTES_LENGTH));
	return p;
}

unsigned char *RklInject_GetAndSetNewSessionKeyIv()
{
	unsigned char *p = rki_iv;
//	PCI_ClearBuffer(p, FILL_RANDOM, 8);
	POYNT_DEBUG("Generated Rki Session Key IV: %s", Bytes2String(p, 8));
	return p;
}

unsigned char *RklTr34_GetSessionKeyIv()
{
	return rki_iv;
}

unsigned char *RklTr34_GetSessionKey()
{
	return rki_session_key;
}

unsigned char *RklTr34_GetRkiEphemeralKey()
{
	return rki_ek;
}

