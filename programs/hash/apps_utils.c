#include "ProtocolDefinitions.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "apps_utils.h"
char STRING_BUFFER[2048];


char *SubString(char *string, unsigned int len)
{
	if (len > sizeof(STRING_BUFFER) / 2)
	{
		return NULL; // too long
	}

	if (string == NULL || len <= 0 || len > (int) sizeof(STRING_BUFFER))
	{
		return NULL;
	}

	memcpy(STRING_BUFFER, string, len);
	STRING_BUFFER[len] = '\0';
	return STRING_BUFFER;

}

unsigned int PCI_ClearBuffer(void *p_buffer, char filltype, unsigned int buffer_length)
{
	switch (filltype)
	{
		case FILL_ZEROES:
			memset(p_buffer, filltype, buffer_length);
			return 0;
		case FILL_RANDOM:
			rng_func(NULL, p_buffer, buffer_length);
			return 0;
		default:
			return 0;
	}
}

int rng_func(void *unused, unsigned char *r, size_t rand_byteLen)
{
	int i;
	for (i = 0; i < rand_byteLen; i++)
	{
		r[i] = rand();
	}
	return 0;

}

char *Bytes2String(unsigned char *bytes, unsigned int len)
{
	unsigned char over = 0;
	if (len > sizeof(STRING_BUFFER) / 2)
	{
		len = sizeof(STRING_BUFFER) / 2;
		over = 1;
	}

	if (bytes == NULL || len <= 0 || len > sizeof(STRING_BUFFER))
	{
		return NULL;
	}

	unsigned int i = 0;

	memset (STRING_BUFFER, 0, sizeof(STRING_BUFFER));
	for (i = 0; i < len; i++)
	{

		unsigned char c = bytes[i];
		unsigned char c1 = '0';
		if (c >= 0xF)
		{
			c1 = (unsigned char) ((c & 0xF0) >> 4);
			c1 = (unsigned char) (c1 < 10 ? c1 + '0' : (c1 - 10) + 'A');
		}
		STRING_BUFFER[i * 2] = c1;

		unsigned char c2 = (unsigned char) (c & 0x0F);
		c2 = (unsigned char) (c2 < 10 ? c2 + '0' : (c2 - 10) + 'A');
		STRING_BUFFER[i * 2 + 1] = c2;
	}
	STRING_BUFFER[len * 2] = '\0';
	if (over)
	{
		STRING_BUFFER[len * 2 - 1] = ']';
		STRING_BUFFER[len * 2 - 2] = '.';
		STRING_BUFFER[len * 2 - 3] = '.';
		STRING_BUFFER[len * 2 - 4] = '[';
	}

	return STRING_BUFFER;
}



/**
 * "12AB" -> {0x12, 0xAB}
 * "1F" -> {0x1F}
 */
int An2Bytes(char *alphanumerics, unsigned char *bytes, unsigned int anLen)
{
	unsigned int i;
	if ((anLen % 2) && anLen == 0)
	{
		return 1;
	}

	for (i = 0; i < anLen; i++)
	{
		char c1 = alphanumerics[i]; //"1"
		char c2 = alphanumerics[i + 1]; // "F"
		int j = i / 2;
		bytes[j] = (unsigned char) ((c1 < 'A' ? c1 - '0' : c1 - 'A' + 10) << 4);
		bytes[j] = (unsigned char) (bytes[j] | (c2 < 'A' ? c2 - '0' : c2 - 'A' + 10));
		i++;
	}
	return 0;
}

// For debug
char *Poynt_ToRepStatusName(int num)
{
	switch (num)
	{
		case REP_STATUS_SUCCESS:
			return "SUCCESS";
		case REP_STATUS_ERR_FAIL:
			return "FAIL";
		case REP_STATUS_ERR_CRC_CHECK:
			return "ERR_CRC_CHECK";
		case REP_STATUS_UNSUPPORTED_PROTOCOL:
			return "UNSUPPORTED_PROTOCOL";
		case REP_STATUS_UNRECOGNIZED_CMD:
			return "UNRECOGNIZED_CMD";
		case REP_STATUS_UNSUPPORTED_CMD:
			return "UNSUPPORTED_CMD";
		case REP_STATUS_CMD_NOT_ALLOWED:
			return "CMD_NOT_ALLOWED";
		case REP_STATUS_ERR_SEQ_NUM_REPEATED:
			return "ERR_SEQ_NUM_REPEATED";
		case REP_STATUS_ERR_CANCELLED_CMD:
			return "ERR_CANCELLED_CMD";
		case REP_STATUS_BUFFER_OVERFLOW:
			return "BUFFER_OVERFLOW";
		case REP_STATUS_ERR_PARTIAL_CMD:
			return "ERR_PARTIAL_CMD";
		case REP_STATUS_ERR_TIMEOUT:
			return "TIMEOUT";
		case REP_STATUS_BAD_PARAMETER:
			return "BAD_PARAMETER";
		case REP_STATUS_PARSING_ERROR:
			return "PARSING_ERROR";
		case REP_STATUS_BUILDER_ERROR:
			return "BUILDER_ERROR";


		case REP_STATUS_INVALID_KEY_SLOT:
			return "INVALID_KEY_SLOT";
		case REP_STATUS_ENCRYPTION_KEY_NOT_FOUND:
			return "ENCRYPTION_KEY_NOT_FOUND";
		case REP_STATUS_INVALID_ENCRYPTION_KEY_FORMAT:
			return "INVALID_ENCRYPTION_KEY_FORMAT";
		case REP_STATUS_INVALID_MAC:
			return "INVALID_MAC";
		case REP_STATUS_DUKPT_KEY_EOL:
			return "DUKPT_KEY_EOL";
		case REP_STATUS_SECURITY_NOT_ENABLED:
			return "SECURITY_NOT_ENABLED";
		case REP_STATUS_TOO_FEW_COMPONENTS:
			return "TOO_FEW_COMPONENTS";
		case REP_STATUS_ERR_DUPLICATE_KEY:
			return "DUPLICATE_KEY";
		case REP_STATUS_TAMPER_ERROR:
			return "TAMPER_ERROR";
		case REP_STATUS_ERR_GT4_CALIBRATION:
			return "ERR_GT4_CALIBRATION";
		case REP_STATUS_ROOT_CERT_ALREADY_LOADED:
			return "ROOT_CERT_ALREADY_LOADED";
		case REP_STATUS_CERT_NOT_TRUSTED:
			return "CERT_NOT_TRUSTED";
		case REP_STATUS_INVALID_CERT:
			return "INVALID_CERT";
		case REP_STATUS_CERT_NOT_FOUND:
			return "CERT_NOT_FOUND";
		case REP_STATUS_ERR_PED_KEY_DELIVERY:
			return "PED_KEY_DELIVERY";
		case REP_STATUS_INVALID_SIGNATURE:
			return "INVALID_PED_SIGNATURE";
		case REP_STATUS_PED_MORE_KEYS_AVAILABLE:
			return "PED_MORE_KEYS_AVAILABLE";
		case REP_STATUS_ENCRYPTION_FAILED:
			return "ENCRYPTION_FAILED";
		default:
			return "";
	}
}


int isZeroized(unsigned char *p, int len)
{
	int i = 0;
	char r = 0;
	for (i = 0; i < len; i++)
	{
		r |= (p[i] ^ 0x00);
	}
	return (r == 0 ? TRUE : FALSE);
}
int Encrypt3DesCbc(unsigned char *dataOut, unsigned char *dataIn, unsigned char *key, unsigned char *IV,
				   unsigned int data_byteLen)
{
	memset(dataOut, 0xFF, data_byteLen);
	return 0;
}
void ApplyPKCS5Padding(unsigned char *data, unsigned short dataLen, unsigned short *paddedDataLen)
{
	unsigned short padLen = (unsigned short) (8 - dataLen % 8);
	memset(data + dataLen, padLen, padLen);
	*paddedDataLen = padLen;
}
