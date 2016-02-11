//
// Created by Emmanuel Texier on 2/5/16.
//

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

#endif

#ifndef MBED_TLS_RKL_ASN1_H
#define MBED_TLS_RKL_ASN1_H


typedef struct kn_asn1
{
	mbedtls_x509_buf raw;               /**< The raw certificate data (DER). */
	mbedtls_x509_buf tbs;               /**< The raw certificate body (DER). The part that is To Be Signed. */

	int version;                /**< The X.509 version. (1=v1, 2=v2, 3=v3) */
	mbedtls_x509_buf serial;            /**< Unique id for certificate issued by a specific CA. */
	mbedtls_x509_buf sig_oid;           /**< Signature algorithm, e.g. sha1RSA */

	mbedtls_x509_buf issuer_raw;        /**< The raw issuer data (DER). Used for quick comparison. */
	mbedtls_x509_buf subject_raw;       /**< The raw subject data (DER). Used for quick comparison. */

	mbedtls_x509_name issuer;           /**< The parsed issuer data (named information object). */
	mbedtls_x509_name subject;          /**< The parsed subject data (named information object). */

	mbedtls_x509_time valid_from;       /**< Start time of certificate validity. */
	mbedtls_x509_time valid_to;         /**< End time of certificate validity. */

	mbedtls_pk_context pk;              /**< Container for the public key context. */

	mbedtls_x509_buf issuer_id;         /**< Optional X.509 v2/v3 issuer unique identifier. */
	mbedtls_x509_buf subject_id;        /**< Optional X.509 v2/v3 subject unique identifier. */
	mbedtls_x509_buf v3_ext;            /**< Optional X.509 v3 extensions.  */
	mbedtls_x509_sequence subject_alt_names;    /**< Optional list of Subject Alternative Names (Only dNSName supported). */

	int ext_types;              /**< Bit string containing detected and parsed extensions */
	int ca_istrue;              /**< Optional Basic Constraint extension value: 1 if this certificate belongs to a CA, 0 otherwise. */
	int max_pathlen;            /**< Optional Basic Constraint extension value: The maximum path length to the root certificate. Path length is 1 higher than RFC 5280 'meaning', so 1+ */

	unsigned int key_usage;     /**< Optional key usage extension value: See the values in x509.h */

	mbedtls_x509_sequence ext_key_usage; /**< Optional list of extended key usage OIDs. */

	unsigned char ns_cert_type; /**< Optional Netscape certificate type extension value: See the values in x509.h */

	mbedtls_x509_buf sig;               /**< Signature: hash of the tbs part signed with the private key. */
	mbedtls_md_type_t sig_md;           /**< Internal representation of the MD algorithm of the signature algorithm, e.g. MBEDTLS_MD_SHA256 */
	mbedtls_pk_type_t sig_pk;           /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. MBEDTLS_PK_RSA */
	void *sig_opts;             /**< Signature options to be passed to mbedtls_pk_verify_ext(), e.g. for RSASSA-PSS */

	struct kn_asn1 *next;     /* next key structure */
} ksn_asn1_t;

#endif //MBED_TLS_RKL_ASN1_H
