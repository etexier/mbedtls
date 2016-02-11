/*
 * CommandDefinitions.h
 *
 *  Created on: Apr 22, 2015
 *      Author: pubuduk
 */

#ifndef PROTOCOL_DEFINITIONS_H_
#define PROTOCOL_DEFINITIONS_H_


// Poynt Commands
#define REP_STATUS Poynt_ToRepStatusName
#define RS(_X_) REP_STATUS(_X_), _X_

#define TR34_sha256WithRSAEncryption "1.2.840.113549.1.1.11"
#define TR34_RSAES_OAEP "1.2.840.113549.1.1.7"
#define TR34_SHA256 "2.16.840.1.101.3.4.2.1"


// use https://www.viathinksoft.com/~daniel-marschall/asn.1/oid-converter/online.php OID converter, you must remove the first 2 bytes
// '1.2.840.113549.1.1.7'
#define OID_RSAES_OAEP "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x07"
// 1.2.840.113549.1.1.8
#define OID_MGF1 "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x08"
// 1.2.840.113549.1.1.9
#define OID_PSPECIFIED "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x09"

// 1.2.840.113549.1.7.1
#define OID_PKCS7_DATA "\x2A\x86\x48\x86\xF7\x0D\x01\x07\x01"

#define OID_ADD_LEN(_X_) _X_, sizeof(_X_)-1
#define ENSURE_POYNT_MBEDTLS_INITIALIZED {while(0) {};}
#define NO_ERROR 0

#ifndef TRUE
#define TRUE	(1)
#endif

#ifndef FALSE
#define FALSE	(0)
#endif

#ifndef NULL
#define NULL 	((void *)0)
#endif

// Poynt Commands
#define REP_STATUS Poynt_ToRepStatusName
#define RS(_X_) REP_STATUS(_X_), _X_

#define CMD_PING								0x0101
#define CMD_BUZZER_PATTERN_TEST					0x0102
#define CMD_CT_CARD_TEST						0x0103
#define CMD_CL_CARD_TEST						0x0104
#define CMD_MSR_TEST							0x0105
#define CMD_CIRQUE_AFE_DATA_PRESENCE_TEST		0x0106
#define CMD_EXT_FLASH_FULL_TEST					0x0107
#define CMD_TAMPER_TEST							0x0108
#define CMD_EXT_FLASH_QUICK_TEST				0x0109
#define CMD_BUZZER_ON_OFF_TEST					0x010A
#define CMD_PCI_PHY_TEST_LOAD_KEY               0x0180
#define CMD_PCI_PHY_TEST_GET_KEY_STATE          0x0181
#define CMD_GET_PIN								0x0183

#define CMD_DO_GCOV                             0x01FA
#define CMD_GET_GCOV_DATA                       0x01FB
#define CMD_REMOVE_GCOV_DATA                    0x01FC

#define CMD_SET_RF_TUNING_PARAMS				0x0150
#define CMD_GET_RF_TUNING_PARAMS				0x0151
#define CMD_CL_EMV_ANALOG_TEST					0x0152
#define CMD_CL_EMV_L1_LOOPBACK_TEST				0x0153
#define CMD_CT_EMV_L1_LOOPBACK_TEST				0x0154

#define CMD_GET_FIRMWARE_VERSION				0x0200
#define CMD_GET_FIRMWARE_COMPONENT_VERSION		0x0201
#define CMD_GET_PROCESSOR_TYPE					0x0202
#define CMD_GET_PROCESSOR_ID					0x0203
#define CMD_GET_SERIAL_NUM						0x0204
#define CMD_SET_SERIAL_NUM						0x0205
#define CMD_GET_TAMPER_INFO						0x0206
#define CMD_GET_RTC								0x0207
#define CMD_SET_RTC								0x0208
#define CMD_GET_CIRQUE_FIRMWARE_VERSION			0x0209
#define CMD_GET_CIRQUE_FIRMWARE_ID				0x020A

#define CMD_GET_TOUCH_SAMPLING_RATE				0x020B
#define CMD_SET_TOUCH_SAMPLING_RATE				0x020C

#define CMD_GET_HARDWARE_CONFIGURATION			0x020E
#define CMD_ENTER_POWER_SAVE_MODE           	0x020F

#define CMD_GET_BOARD_ID						0x0210
#define CMD_GET_TAMPER_STATUS                   0x0213
#define CMD_GET_ROM_INFO						0x0214
#define CMD_GET_FIRMWARE_BUILD_VERSION          0x0215
#define CMD_GET_FIRMWARE_REVISION		        0x0216
#define CMD_GET_CIRQUE_REGISTER_VALUE			0x0217

#define CMD_CANCEL								0x0300
#define CMD_PERFORM_TRANSACTION					0x0301
#define CMD_CONTINUE_TRANSACTION_AFTER_APP_SELECTION				0x0302
#define CMD_COMPLETE_TRANSACTION				0x0303
#define CMD_CONTINUE_TRANSACTION_AFTER_REDE_SPECIAL_FLOW				0x0304



#define CMD_LOAD_EMV_CONFIGURATION_BINARY_FILE   	(0x037F)
#define CMD_LOAD_EMV_CONFIGURATION_BINARY_FILE_CF_FIRST_AND_ONLY   (0x00)
#define CMD_LOAD_EMV_CONFIGURATION_BINARY_FILE_CF_FIRST            (0x01)
#define CMD_LOAD_EMV_CONFIGURATION_BINARY_FILE_CF_MIDDLE           (0x02)
#define CMD_LOAD_EMV_CONFIGURATION_BINARY_FILE_CF_LAST             (0x03)

#define CMD_SET_TERMINAL_CONFIGURATION				(0x0350)
#define CMD_GET_TERMINAL_CONFIGURATION				(0x0351)
#define CMD_SET_TERMINAL_CONFIGURATION_TO_DEFAULT	(0x0352)

#define CMD_SET_AID_CONFIGURATION 					(0x0360)
#define CMD_GET_AID_CONFIGURATION 					(0x0361)
#define CMD_SET_AID_CONFIGURATION_TO_DEFAULT 		(0x0362)
#define CMD_DELETE_AID_CONFIGURATION 				(0x0363)

#define CMD_SET_EMV_CA_PUBLIC_KEY					(0x0370)
#define CMD_DELETE_EMV_CA_PUBLIC_KEY				(0x0371)
#define CMD_DELETE_ALL_EMV_CA_PUBLIC_KEYS			(0x0372)
#define CMD_GET_EMV_PUBLIC_KEY_RID_AND_INDICES		(0x0373)

#define CMD_SET_EMV_CONFIGURATION_TAG_VALUE 		(0x037D)
#define CMD_GET_EMV_CONFIGURATION_TAG_VALUE 		(0x037E)

#define CMD_ADD_EMV_REVOCATION_LIST_ENTRY			(0x0380)
#define CMD_GET_EMV_REVOCATION_LIST					(0x0381)
#define CMD_DELETE_EMV_REVOCATION_LIST_ENTRY		(0x0382)
#define CMD_DELETE_EMV_REVOCATION_LIST				(0x0383)

#define CMD_ADD_EMV_EXCEPTION_LIST_ENTRY			(0x0390)
#define CMD_GET_EMV_EXCEPTION_LIST					(0x0391)
#define CMD_DELETE_EMV_EXCEPTION_LIST_ENTRY			(0x0392)
#define CMD_DELETE_EMV_EXCEPTION_LIST				(0x0393)

#define CMD_DESTROY_ALL_CONFIGURATIONS 				(0x03A0)
#define CMD_DELETE_ALL_AID_CONFIGURATIONS 			(0x0364)

#define CMD_GET_TORN_TRANSACTION_LOG 				(0x0310)
#define CMD_CLEAN_TORN_TRANSACTION_LOG 				(0x0311)
#define CMD_DELETE_TORN_TRANSACTION_LOG 			(0x0312)
#define CMD_STOP							 		(0x0313)

#define CMD_CRYPTO									0x0401

#define CMD_POWER_OFF_STATUS						0x0600
// Test
#define CMD_TEST									0xFF01
#define CMD_FACTORY_RESET							0xFF02


//
// Key Management
// See Poynt PCI Management specification
//
#define CMD_ENABLE_PCI_SECURITY						0x0500
#define CMD_LOAD_PLAINTEXT_KEK_COMPONENT			0x0501
#define CMD_LOAD_KEY_ENCRYPTION_KEY 				0x0502
#define CMD_LOAD_INITIAL_DUKPT_KEY					0x0503
#define CMD_ERASE_ALL_KEYS							0x0504
#define CMD_LOAD_MASTER_KEY							0x0505
#define CMD_LOAD_SESSION_KEY						0x0506
#define CMD_GET_PCI_SECURITY_STATUS 				0x0520
#define CMD_GET_PCI_KEY_STATUS						0x0521
#define CMD_DISABLE_EMPTY_KEK_SLOTS					0x0522
#define CMD_ENABLE_DISABLED_KEK_SLOTS				0x0523
#define CMD_DECOMMISSION_READER						0x0526
#define CMD_GET_DUKPT_PIN_PCI_PHYSICAL_TEST 		0x0580
#define CMD_SELECT_DUKPT_PIN_ENCRYPTION_KEY_SLOT	0x0581
#define CMD_SELECT_DUKPT_DATA_ENCRYPTION_KEY_SLOT	0x0582
#define CMD_SELECT_MASTER_SESSION_PIN_ENCRYPTION_KEY_SLOT	0x0583
#define CMD_SELECT_MASTER_SESSION_DATA_ENCRYPTION_KEY_SLOT	0x0584
#define CMD_GET_DUKPT_DATA							0x0585
#define CMD_GET_SELECTED_KEY_SLOTS					0x0586
#define CMD_GET_NEW_DUKPT_PIN				 		0x0587


#define CMD_LOAD_TRUSTED_SOURCE_PUBLIC_KEY			0x0524
#define CMD_GET_KEK_KSN         					0x0525

#define CMD_GET_SECURITY_EVENT_LOG          		0x058A
#define CMD_CLEAR_SECURITY_EVENT_LOG        		0x058B
//
// Ad hoc crypto
//
#define CMD_GENERATE_TERMINAL_KEY_PAIR				0x05A0
#define CMD_GET_TERMINAL_PUBLIC_KEY					0x05A1
#define CMD_SIGN_TERMINAL_DATA						0x05A2

//
// Remote Key Loading support (RKL)
//

// For CSR and CERT

#define CMD_GET_DEVICE_SIGNING_CSR                      0x05B0
#define CMD_GET_CERTS_STATUS							0x05B1
#define CMD_SET_DEVICE_SIGNING_CERT                     0x05B2
#define CMD_GET_DEVICE_SIGNING_CERT_SUMMARY          	0x05B3
#define CMD_GET_DEVICE_SIGNING_CERT                     0x05B4

// Trusted cert loading
#define CMD_LOAD_TRUSTED_CERT			                0x05B5
#define CMD_GET_TRUSTED_CERTS_SUMMARY                   0x05B6


// For Transaction Encryption Key exchange
// See Futurex-RKMS-Series-TechRef Version commands p25
#define CMD_GET_PEDI_REQUEST                  0x05C0
#define CMD_SET_PEDI_RESPONSE                 0x05C1

#define CMD_GET_PEDK_INITIAL_REQUEST          0x05C2
#define CMD_GET_PEDK_CONTINUATION_REQUEST     0x05C3
#define CMD_SET_PEDK_RESPONSE                 0x05C4

#define CMD_GET_PEDV_REQUEST                  0x05C5
#define CMD_SET_PEDV_RESPONSE                 0x05C6



// Poynt Response Status Codes
#define REP_STATUS_SUCCESS						0x00	// The command was executed successfully
#define	REP_STATUS_ERR_FAIL						0x01	// This is a generic failure message
#define REP_STATUS_ERR_CRC_CHECK				0x02	// CRC Check failed on a received command packet
#define REP_STATUS_UNSUPPORTED_PROTOCOL        0x03	// The specified Poynt Protocol is not supported. This error is reported if the protocol version is not supported.
#define REP_STATUS_UNRECOGNIZED_CMD            0x04	// The command is an unknown command
#define REP_STATUS_UNSUPPORTED_CMD            0x05	// The command specified is no longer supported
#define REP_STATUS_CMD_NOT_ALLOWED            0x06 	// The command is recognized and supported but is not allowed at that specific point due to some pre-condition not being met.
#define REP_STATUS_ERR_SEQ_NUM_REPEATED			0x07	// A command was received with a serial number that has already been used.
// The terminal has either used the wrong serial number or is trying to re-send a command that has already been received.
#define REP_STATUS_ERR_CANCELLED_CMD			0x08	// The command was cancelled via a Cancel command
#define REP_STATUS_BUFFER_OVERFLOW            	0x09	// A Command Data Length exceeds the maximum allowed length
#define REP_STATUS_ERR_PARTIAL_CMD				0x0A	// All command was received partially and a USB receive timeout occurred while waiting for the remainder
#define REP_STATUS_BAD_PARAMETER            	0x0C	// The command or the command data had an invalid parameter
#define REP_STATUS_ERR_START_B					0x0D	// We have to perform a new transaction at Entry Point B
#define REP_STATUS_ERR_ILLEGAL_STATE			0x0E	// Firmware is in a bad state. Internal error
#define REP_STATUS_PARSING_ERROR				0x0F	// Parsing error
#define REP_STATUS_ERR_TIMEOUT					0x10	// A timeout occurred
#define REP_STATUS_BUILDER_ERROR                0x11	// Message builder error


// Transaction Status codes

#define TRANSACTION_STATUS_OFFLINE_APPROVED				0x00000200	// The transaction was approved offline
#define TRANSACTION_STATUS_OFFLINE_DECLINED				0x00000201	// The transaction was declined offline
#define TRANSACTION_STATUS_ONLINE_AUTH_REQUIRED			0x00000202	// The transaction must be sent online to the back-end system
// for a final decision of approved or declined. When this status
// code is returned, Online PIN Verification may also need to be performed
// if an enciphered PIN is present in the response data.
#define TRANSACTION_STATUS_ADVICE_REQUIRED				0x00000203	// The transaction was declined and an advice is required.
#define TRANSACTION_STATUS_REVERSAL_REQUIRED			0x00000204	// The transaction was declined and a reversal is required.
#define TRANSACTION_STATUS_ADVICE_AND_REVERSAL_REQUIRED	0x00000205	// The transaction was declined and both advice and reversal are required.
#define TRANSACTION_STATUS_COLLISION_DETECTED			0x00000206	// Multiple contactless cards found. Try again with a single contactless card.
#define TRANSACTION_STATUS_CANCELLED					0x00000207
#define TRANSACTION_STATUS_TRY_ANOTHER_INTERFACE		0x00000208
#define TRANSACTION_STATUS_CARD_APP_SEL_RETRY_REQ		0x0000020A	// The transaction needs cardholder interaction to select another
// card application or to confirm the selection of another application
// since the previous application was not accepted.
//PR-499 & PR-500
#define TRANSACTION_STATUS_REDE_SPECIAL_FLOW_REQUIRED   0x0000020B  //The transaction needs the terminal to re-calculate the Amount
//based on the card data items it returns.
#define TRANSACTION_STATUS_ONLINE_APPROVED				0x00000210	// The transaction was approved online.
#define TRANSACTION_STATUS_ONLINE_DECLINED				0x00000211	// The transaction was declined online.
#define TRANSACTION_STATUS_NOT_ACCEPTED					0x00000212	// The card application is not supported or there is
// a restriction on the use of the application.
#define REP_STATUS_PINS_MISMATCH					(0x00000213)



#define TRANSACTION_STATUS_CARD_HOLDER_APP_SELECTION_REQUIRED		0x00000209	// The transaction needs cardholder interaction to select a card

// Custom Status Codes. Internal Only
#define REP_STATUS_NO_RESPONSE							0xFFFFFFFF

//
// Poynt Response Status Codes related to PCI Key Management
// See Poynt PCI Key Management Specification
//
#define REP_STATUS_INVALID_KEY_SLOT 	   			(0x00008000)
#define REP_STATUS_ENCRYPTION_KEY_NOT_FOUND 		(0x00008001)
#define REP_STATUS_INVALID_ENCRYPTION_KEY_FORMAT	(0x00008002)
#define REP_STATUS_INVALID_MAC           (0x00008003)
#define REP_STATUS_DUKPT_KEY_EOL					(0x00008004)
#define REP_STATUS_SECURITY_NOT_ENABLED    			(0x00008005)
#define REP_STATUS_TOO_FEW_COMPONENTS				(0x00008006)
#define REP_STATUS_ERR_DUPLICATE_KEY				(0x00008007)
#define REP_STATUS_TAMPER_ERROR         			(0x00008008)
#define REP_STATUS_ERR_GT4_CALIBRATION         		(0x00008009)

// Cert specific errors
#define REP_STATUS_ROOT_CERT_ALREADY_LOADED  		(0x0000800A)
#define REP_STATUS_CERT_NOT_TRUSTED        			(0x0000800B)
#define REP_STATUS_INVALID_CERT                		(0x0000800C)
#define REP_STATUS_CERT_NOT_FOUND           		(0x0000800D)

// RKI Errors
#define REP_STATUS_ERR_PED_KEY_DELIVERY        		(0x0000800E)
#define REP_STATUS_INVALID_SIGNATURE            	(0x0000800F)
#define REP_STATUS_PED_MORE_KEYS_AVAILABLE 			(0x00008010)
#define REP_STATUS_INVALID_ASN1 	     	  		(0x00008011)
#define REP_STATUS_ENCRYPTION_FAILED 	     	    (0x00008012)


//	Poynt Notification Types
//#define NOTIFICATION_FLAGS 	 					0x00000000
//#define UI_EVENT_NOTIFICATION   				0x00000001
//#define COMMAND_RECEIVED_NOTIFICATION   		0x00000002
//#define SECURITY_EVENT_NOTIFICATION   			0x00000003
//#define MISCELLANEOUS_EVENT						0x7fffffff


//	Poynt UI Events
#define UI_IDLE									0x00000000
#define UI_READY_PRESENT_CARD					0x00000001
#define UI_READY_INSERT_CARD					0x00000002
#define UI_READY_SWIPE_CARD						0x00000003
#define UI_READY_INSERT_CARD_OR_SWIPE_CARD		0x00000004
#define UI_READY_INSERT_SWIPE_OR_ANOTHER		0x00000005
#define UI_READY_PRESENT_CARD_AGAIN				0x00000006
#define UI_TIMEOUT								0x00000007
#define UI_PROCESSING							0x00000008
#define UI_CART_READ_SUCCESSFULLY				0x00000009
#define UI_PROCESSING_ERROR_CL					0x0000000A
#define UI_PROCESSING_ERROR_COLLISION			0x0000000B
#define UI_PROCESSING_ERROR_SEE_PHONE			0x0000000C
#define UI_PROCESSING_ERROR						0x0000000D
#define UI_NOT_ACCEPTED							0x0000000E
#define UI_CARD_NOT_REMOVED						0x0000000F
#define UI_CARD_REMOVED							0x00000010
#define UI_ONLINE_ATHURIZATION					0x00000011
#define UI_APPROVED								0x00000012
#define UI_APPROVED_WITH_SIGNATURE				0x00000013
#define UI_DECLINED								0x00000014
#define UI_CANCELLED_POLLING					0x00000015
#define UI_CANCELLED_TRANSACTION				0x00000016
#define UI_CALL_YOUR_BANK						0x00000017
#define UI_PIN_ENTRY_REQUIRED					0x00000018
#define UI_PIN_DIGIT_ENTRERED					0x00000019
/*PR-621*/
#define UI_CHANGE_LANGUAGE                      0x00000021
#define UI_PIN_DIGIT_DELETED					0x0000001A
#define UI_PIN_CLEARED							0x0000001B
#define UI_PIN_CANCELLED						0x0000001C
#define UI_PIN_ENTRERED							0x0000001D
#define UI_PIN_INCORECT							0x0000001E
#define UI_PIN_OK								0x0000001F
#define UI_PIN_TIME_OUT                         0x00000020

#define MISC_CARD_INSERTED						0x00000001
#define MISC_READER_REBOOTING                   0x00000002
#define MISC_READER_REBOOTING_ALL_OK            (0x00)
#define MISC_READER_REBOOTING_SELF_CHECK_FAILED (0X01)

#define SEC_DEVICE_SECURE						0x00000000
#define SEC_TAMPER_TRIGGRED						0x00000001
#define SEC_ACTIVE_TAMPER_PRESENT				0x00000002
#define SEC_TOUCH_PAD_INTRUSION_DETECTED		0x00000003
#define SEC_GT4_INTEGRITY_FAILED				0x00000004
#define SEC_KEY_VALIDATION_FAILED				0x00000005
#define SEC_SECURITY_REGISTER_CHECK_FAILED		0x00000006
#define SEC_RKI_FAILED                          0x00000007


typedef enum
{
	// aync job to do, caused by USB command, enter low power mode 'Idle' status
			JOB_USBCMD_ENTER_POWERMODE_IDLE = 1,

	//one bit flags as one job that's pending to execute at a suitable time,
	// or a field of several bits identify a number of different jobs, e.g. 3 bits to index 8 jobs

} job_scheduled_t;


#define ENSURE_NULL_CMD_DATA_LEN \
	UNUSED(cmd_data); \
	if (cmd_data_len != 0) \
	{ \
		POYNT_ERROR("Invalid cmd data length %u, exp. 0", cmd_data_len); \
		*resp_data_len = 0; \
		return REP_STATUS_BAD_PARAMETER; \
	}

#define ENSURE_NOT_NULL_CMD_DATA_LEN \
	if (cmd_data_len == 0) \
	{ \
		POYNT_ERROR("Invalid cmd data length %u, exp. !=0", cmd_data_len); \
		*resp_data_len = 0; \
		return REP_STATUS_BAD_PARAMETER; \
	}

#endif /* PROTOCOL_DEFINITIONS_H_ */
