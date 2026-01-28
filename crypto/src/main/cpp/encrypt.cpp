//
// Created on 2026/1/26.
//
// Node APIs are not fully supported. To solve the compilation error of the interface cannot be found,
// please include "napi/native_api.h".

// 配套的头文件
#include "encrypt.h"

// C 语言系统文件

// C++ 标准库头文件
#include <stdexcept>

// 其他库的 .h 文件.
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/types.h"

// 本项目的 .h 文件.
#include "global_init.h"

void cipher::cipher_init(int algName, int mode, int padding) {
    // 初始化openssl evp ctx
    this->ctx = EVP_CIPHER_CTX_new();
    if (this->ctx == nullptr) {
        ERR_print_errors_cb(global_init::openssl_error_callback, nullptr);
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }
    switch (algName) {}
    EVP_CIPHER_CTX_set_padding(this->ctx, padding);
}

void cipher::cipher_update() {}

void cipher::cipher_final() {}