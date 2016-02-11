//
// Created by Emmanuel Texier on 2/10/16.
//

#ifndef MBED_TLS_RKL_DB_H_H
#define MBED_TLS_RKL_DB_H_H

#define CERT_MAXSIZE 1024
#define RMKS_CERT(_X_) _X_->len, Bytes2String(_X_->der, _X_->len)
struct cert_der {
	unsigned short len;
	unsigned char der[CERT_MAXSIZE];
};

typedef struct cert_der rkms_cert_der_t;


unsigned int RklDb_GetWorkingRkmsEncryptionCert(rkms_cert_der_t *cert);
unsigned int RklDb_GetWorkingRkmsSigningCert(rkms_cert_der_t *cert);

#endif //MBED_TLS_RKL_DB_H_H
