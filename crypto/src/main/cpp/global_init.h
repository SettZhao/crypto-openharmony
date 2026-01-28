//
// Created on 2026/1/26.
//
// Node APIs are not fully supported. To solve the compilation error of the interface cannot be found,
// please include "napi/native_api.h".

#ifndef CRYPTO_OPENHARMONY_OPENSSL_INIT_H
#define CRYPTO_OPENHARMONY_OPENSSL_INIT_H

#include <cstddef>
class global_init {
public:
    static int openssl_error_callback(const char *str, size_t len, void *u);
    static bool globalInit();
};

#endif // CRYPTO_OPENHARMONY_OPENSSL_INIT_H
