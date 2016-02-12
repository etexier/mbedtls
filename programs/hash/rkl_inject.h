//
// Created by Emmanuel Texier on 2/10/16.
//

#ifndef MBED_TLS_RKL_INJECT_H
#define MBED_TLS_RKL_INJECT_H

unsigned char *RklInject_GetAndSetNewSessionKeyIv();
unsigned char *RklInject_GetAndSetNewSessionKey();
unsigned char *RklInject_GetAndSetNewEphemeralKey();
unsigned char *RklTr34_GetSessionKey();
unsigned char *RklTr34_GetRkiEphemeralKey();
unsigned char *RklTr34_GetSessionKeyIv();
char *RklInject_GetAndSetNewDeviceNonce();

#endif //MBED_TLS_RKL_INJECT_H
