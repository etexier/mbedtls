//
// Created by Emmanuel Texier on 2/10/16.
//
#include "rkl_inject.h"
#include "apps_utils.h"
#include "ProtocolDefinitions.h"
#include "tr34_types.h"
unsigned char *rki_session_key;
unsigned char *rki_ek;
unsigned char *rki_iv;


unsigned char *RklInject_GetAndSetNewSessionKey()
{
	unsigned char *p = rki_session_key;
	PCI_ClearBuffer(p, FILL_RANDOM, TDES_KEY_BYTES_LENGTH);
	POYNT_DEBUG("Generated Rki Session Key: %s", Bytes2String(p, TDES_KEY_BYTES_LENGTH));
	return p;
}

unsigned char *RklInject_GetAndSetNewEphemeralKey()
{
	unsigned char *p = rki_ek;
	PCI_ClearBuffer(p, FILL_RANDOM, TDES_KEY_BYTES_LENGTH);
	POYNT_DEBUG("Generated Rki Ephemeral Key: %s", Bytes2String(p, TDES_KEY_BYTES_LENGTH));
	return p;
}

unsigned char *RklInject_GetAndSetNewSessionKeyIv()
{
	unsigned char *p = rki_iv;
	PCI_ClearBuffer(p, FILL_RANDOM, 8);
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

