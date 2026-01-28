//
// Created on 2026/1/26.
//
// Node APIs are not fully supported. To solve the compilation error of the interface cannot be found,
// please include "napi/native_api.h".

#ifndef CRYPTO_OPENHARMONY_ENCRYPT_H
#define CRYPTO_OPENHARMONY_ENCRYPT_H

#include "openssl/types.h"
class cipher {
    EVP_CIPHER_CTX *ctx;
    void cipher_init(int algName, int mode, int padding);
    void cipher_update();
    void cipher_final();
};

#endif // CRYPTO_OPENHARMONY_ENCRYPT_H
