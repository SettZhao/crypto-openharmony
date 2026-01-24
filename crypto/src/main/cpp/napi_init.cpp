/*
 * Copyright (c) 2026-present crypto-openharmony
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include "napi/native_api.h"
#include "openssl/evp.h"
#include "openssl/provider.h"
#include "openssl/err.h"
#include "securec.h"
#include "utils/hilog_helper.h"
#include "utils/napi_utils.h"
#include <mutex>
#include <string>
#include <cstring>

int openssl_error_callback (const char *str, size_t len, void *u){
    LOGE("openssl error: %{public}s", str);
    return 0;
}

// 全局 provider 指针和互斥锁
static std::once_flag init_flag;
static OSSL_PROVIDER *legacy_provider = nullptr;
static OSSL_PROVIDER *default_provider = nullptr;

bool globalInit(){
    std::call_once(init_flag, [](){
        // 先加载 default provider，再加载 legacy provider
        default_provider = OSSL_PROVIDER_load(nullptr, "default");
        if (default_provider == nullptr) {
            ERR_print_errors_cb(openssl_error_callback, nullptr);
            LOGE("OSSL_PROVIDER_load default failed");
        }
        
        legacy_provider = OSSL_PROVIDER_load(nullptr, "legacy");
        if (legacy_provider == nullptr) {
            ERR_print_errors_cb(openssl_error_callback, nullptr);
            LOGE("OSSL_PROVIDER_load legacy failed");
            throw std::runtime_error("Failed to load legacy provider");
        }
        LOGI("OpenSSL providers loaded successfully");
    });
    return true;
}

napi_value Encrypt(napi_env env, napi_callback_info info){
    // 获取js传入参数
    size_t argc = 5;
    napi_value args[5] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    try {
        globalInit();
    } catch (const std::exception& e) {
        napi_throw_error(env, nullptr, e.what());
        return nullptr;
    }
    
    // 初始化openssl evp ctx
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        ERR_print_errors_cb(openssl_error_callback, nullptr);
        napi_throw_error(env, nullptr, "EVP_CIPHER_CTX_new failed");
        return nullptr;
    }
    
    // 获取加密算法名称/key/iv
    std::string algName = napi_utils::get_string_from_napi_value(env, args[0]);
    size_t keyLen = 0, ivLen = 0;
    unsigned char* keyPtr = napi_utils::get_arraybuffer_from_napi_value(env, args[1], &keyLen);
    unsigned char* ivPtr = napi_utils::get_arraybuffer_from_napi_value(env, args[2], &ivLen);
    
    // 创建key和iv的副本，确保在加密期间内存稳定
    // 重要：使用独立的内存空间，避免OpenSSL修改原始数据
    unsigned char* key = new unsigned char[keyLen];
    unsigned char* iv = new unsigned char[ivLen];
    if (memcpy_s(key, keyLen, keyPtr, keyLen) != EOK) {
        delete[] key;
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        napi_throw_error(env, nullptr, "Failed to copy key");
        return nullptr;
    }
    if (memcpy_s(iv, ivLen, ivPtr, ivLen) != EOK) {
        delete[] key;
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        napi_throw_error(env, nullptr, "Failed to copy iv");
        return nullptr;
    }
    
    LOGI("algName: %{public}s, keyLen: %{public}zu, ivLen: %{public}zu", algName.c_str(), keyLen, ivLen);

    if (algName.empty()) {
        delete[] key;
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        napi_throw_error(env, nullptr, "algName is empty");
        return nullptr;
    } else if (algName == "Blowfish") {
        // 使用 EVP_CIPHER_fetch 获取算法（更现代且稳定的方法）
        EVP_CIPHER *cipher = EVP_CIPHER_fetch(nullptr, "BF-CBC", nullptr);
        if (cipher == nullptr) {
            // 如果 fetch 失败，回退到传统方法
            LOGW("EVP_CIPHER_fetch failed, using EVP_bf_cbc");
            cipher = const_cast<EVP_CIPHER*>(EVP_bf_cbc());
        }
        
        // 完全重置 context，确保干净状态
        if (EVP_CIPHER_CTX_reset(ctx) != 1) {
            LOGW("EVP_CIPHER_CTX_reset warning");
        }
        
        // 关键修复：对于 Blowfish，必须先设置密钥长度，再初始化
        // 分步骤：1. 设置 cipher  2. 设置密钥长度  3. 设置 key/iv
        int ret = EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
        if (ret != 1){
            ERR_print_errors_cb(openssl_error_callback, nullptr);
            if (cipher != EVP_bf_cbc()) {
                EVP_CIPHER_free(cipher);
            }
            delete[] key;
            delete[] iv;
            EVP_CIPHER_CTX_free(ctx);
            napi_throw_error(env, nullptr, ("EVP_EncryptInit_ex (set cipher) failed, code is " + std::to_string(ret)).c_str());
            return nullptr;
        }
        
        // 显式设置密钥长度（Blowfish 支持可变密钥长度）
        ret = EVP_CIPHER_CTX_set_key_length(ctx, keyLen);
        if (ret != 1){
            LOGW("EVP_CIPHER_CTX_set_key_length failed, using default key length");
        }
        
        // 再次调用设置 key 和 iv
        ret = EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
        
        // 如果使用了 fetch，需要释放
        if (cipher != EVP_bf_cbc()) {
            EVP_CIPHER_free(cipher);
        }
        
        if (ret != 1){
            ERR_print_errors_cb(openssl_error_callback, nullptr);
            delete[] key;
            delete[] iv;
            EVP_CIPHER_CTX_free(ctx);
            napi_throw_error(env, nullptr, ("EVP_EncryptInit_ex (set key/iv) failed, code is " + std::to_string(ret)).c_str());
            return nullptr;
        }
        
        // 验证 context 状态
        int actual_key_len = EVP_CIPHER_CTX_key_length(ctx);
        int actual_iv_len = EVP_CIPHER_CTX_iv_length(ctx);
        int block_size = EVP_CIPHER_CTX_block_size(ctx);
        LOGI("Context initialized: key_len=%{public}d, iv_len=%{public}d, block_size=%{public}d", 
             actual_key_len, actual_iv_len, block_size);
    } else {
        delete[] key;
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        napi_throw_error(env, nullptr, "algName is not support");
        return nullptr;
    }
    
    // 获取填充模式
    int padding = napi_utils::get_int32_from_napi_value(env, args[3]);
    LOGI("padding: %{public}d", padding);
    EVP_CIPHER_CTX_set_padding(ctx, padding);
    
    // 获取input并加密
    size_t inl = 0;
    unsigned char* inputPtr = napi_utils::get_arraybuffer_from_napi_value(env, args[4], &inl);
    
    // 创建input的副本（使用安全内存操作）
    unsigned char* input = new unsigned char[inl];
    if (memcpy_s(input, inl, inputPtr, inl) != EOK) {
        delete[] key;
        delete[] iv;
        delete[] input;
        EVP_CIPHER_CTX_free(ctx);
        napi_throw_error(env, nullptr, "Failed to copy input");
        return nullptr;
    }
    
    LOGI("input length: %{public}zu", inl);

    if (input == nullptr || inl == 0) {
        delete[] key;
        delete[] iv;
        delete[] input;
        EVP_CIPHER_CTX_free(ctx);
        napi_throw_error(env, nullptr, "input is empty");
        return nullptr;
    }
    
    // 获取块大小
    int blockSize = EVP_CIPHER_CTX_block_size(ctx);
    // 当关闭填充时，检查输入长度是否是块大小的整数倍
    if (padding == 0 && (inl % blockSize != 0)) {
        delete[] key;
        delete[] iv;
        delete[] input;
        EVP_CIPHER_CTX_free(ctx);
        std::string errMsg = "When padding is disabled, input length (" + std::to_string(inl) + 
                            ") must be a multiple of block size (" + std::to_string(blockSize) + ")";
        LOGE("%{public}s", errMsg.c_str());
        napi_throw_error(env, nullptr, errMsg.c_str());
        return nullptr;
    }
    
    // 分配输出缓冲区(需要比输入大,至少 inl + block_size)
    size_t maxOutLen = inl + blockSize;
    unsigned char* out = new unsigned char[maxOutLen];
    memset(out, 0, maxOutLen);  // 初始化为0，避免垃圾数据
    int outl = 0;
    int cipherLen = 0;  // 初始化为0
    
    if (EVP_EncryptUpdate(ctx, out, &outl, input, (int)inl) != 1){
        ERR_print_errors_cb(openssl_error_callback, nullptr);
        delete[] key;
        delete[] iv;
        delete[] input;
        delete[] out;
        EVP_CIPHER_CTX_free(ctx);
        napi_throw_error(env, nullptr, "EVP_EncryptUpdate failed");
        return nullptr;
    }
    cipherLen += outl;
    
    if (EVP_EncryptFinal_ex(ctx, out + outl, &outl) != 1){
        ERR_print_errors_cb(openssl_error_callback, nullptr);
        delete[] key;
        delete[] iv;
        delete[] input;
        delete[] out;
        EVP_CIPHER_CTX_free(ctx);
        napi_throw_error(env, nullptr, "EVP_EncryptFinal_ex failed");
        return nullptr;
    }
    cipherLen += outl;
    LOGI("cipherLen: %{public}d", cipherLen);
    
    // 清理资源
    EVP_CIPHER_CTX_free(ctx);
    delete[] key;
    delete[] iv;
    delete[] input;
    
    // 创建返回的 ArrayBuffer
    napi_value arraybuffer;
    void* buffer_data = nullptr;
    napi_status status = napi_create_arraybuffer(env, cipherLen, &buffer_data, &arraybuffer);
    if (status != napi_ok || buffer_data == nullptr) {
        delete[] out;
        napi_throw_error(env, nullptr, "napi_create_arraybuffer failed");
        return nullptr;
    }
    
    // 复制加密数据
    int ret = memcpy_s(buffer_data, cipherLen, out, cipherLen);
    delete[] out;  // 释放临时缓冲区
    
    if (ret != EOK) {
        LOGE("memcpy_s failed, ret = %{public}d", ret);
        napi_throw_error(env, nullptr, "memcpy_s failed");
        return nullptr;
    }
    
    return arraybuffer;
}

napi_value Decrypt(napi_env env, napi_callback_info info){
    // 获取js传入参数
    size_t argc = 5;
    napi_value args[5] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    try {
        globalInit();
    } catch (const std::exception& e) {
        napi_throw_error(env, nullptr, e.what());
        return nullptr;
    }
    
    // 初始化openssl evp ctx
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        ERR_print_errors_cb(openssl_error_callback, nullptr);
        napi_throw_error(env, nullptr, "EVP_CIPHER_CTX_new failed");
        return nullptr;
    }
    
    // 获取加密算法名称/key/iv
    std::string algName = napi_utils::get_string_from_napi_value(env, args[0]);
    size_t keyLen = 0, ivLen = 0;
    unsigned char* keyPtr = napi_utils::get_arraybuffer_from_napi_value(env, args[1], &keyLen);
    unsigned char* ivPtr = napi_utils::get_arraybuffer_from_napi_value(env, args[2], &ivLen);
    
    // 创建key和iv的副本，确保在加密期间内存稳定
    // 重要：使用独立的内存空间，避免OpenSSL修改原始数据
    unsigned char* key = new unsigned char[keyLen];
    unsigned char* iv = new unsigned char[ivLen];
    if (memcpy_s(key, keyLen, keyPtr, keyLen) != EOK) {
        delete[] key;
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        napi_throw_error(env, nullptr, "Failed to copy key");
        return nullptr;
    }
    if (memcpy_s(iv, ivLen, ivPtr, ivLen) != EOK) {
        delete[] key;
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        napi_throw_error(env, nullptr, "Failed to copy iv");
        return nullptr;
    }
    
    LOGI("algName: %{public}s, keyLen: %{public}zu, ivLen: %{public}zu", algName.c_str(), keyLen, ivLen);

    if (algName.empty()) {
        delete[] key;
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        napi_throw_error(env, nullptr, "algName is empty");
        return nullptr;
    } else if (algName == "Blowfish") {
        // 使用 EVP_CIPHER_fetch 获取算法（更现代且稳定的方法）
        EVP_CIPHER *cipher = EVP_CIPHER_fetch(nullptr, "BF-CBC", nullptr);
        if (cipher == nullptr) {
            // 如果 fetch 失败，回退到传统方法
            LOGW("EVP_CIPHER_fetch failed, using EVP_bf_cbc");
            cipher = const_cast<EVP_CIPHER*>(EVP_bf_cbc());
        }
        
        // 完全重置 context，确保干净状态
        if (EVP_CIPHER_CTX_reset(ctx) != 1) {
            LOGW("EVP_CIPHER_CTX_reset warning");
        }
        
        // 关键修复：对于 Blowfish，必须先设置密钥长度，再初始化
        // 分步骤：1. 设置 cipher  2. 设置密钥长度  3. 设置 key/iv
        int ret = EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
        if (ret != 1){
            ERR_print_errors_cb(openssl_error_callback, nullptr);
            if (cipher != EVP_bf_cbc()) {
                EVP_CIPHER_free(cipher);
            }
            delete[] key;
            delete[] iv;
            EVP_CIPHER_CTX_free(ctx);
            napi_throw_error(env, nullptr, ("EVP_EncryptInit_ex (set cipher) failed, code is " + std::to_string(ret)).c_str());
            return nullptr;
        }
        
        // 显式设置密钥长度（Blowfish 支持可变密钥长度）
        ret = EVP_CIPHER_CTX_set_key_length(ctx, keyLen);
        if (ret != 1){
            LOGW("EVP_CIPHER_CTX_set_key_length failed, using default key length");
        }
        
        // 再次调用设置 key 和 iv
        ret = EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);
        
        // 如果使用了 fetch，需要释放
        if (cipher != EVP_bf_cbc()) {
            EVP_CIPHER_free(cipher);
        }
        
        if (ret != 1){
            ERR_print_errors_cb(openssl_error_callback, nullptr);
            delete[] key;
            delete[] iv;
            EVP_CIPHER_CTX_free(ctx);
            napi_throw_error(env, nullptr, ("EVP_EncryptInit_ex (set key/iv) failed, code is " + std::to_string(ret)).c_str());
            return nullptr;
        }
        
        // 验证 context 状态
        int actual_key_len = EVP_CIPHER_CTX_key_length(ctx);
        int actual_iv_len = EVP_CIPHER_CTX_iv_length(ctx);
        int block_size = EVP_CIPHER_CTX_block_size(ctx);
        LOGI("Context initialized: key_len=%{public}d, iv_len=%{public}d, block_size=%{public}d", 
             actual_key_len, actual_iv_len, block_size);
    } else {
        delete[] key;
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        napi_throw_error(env, nullptr, "algName is not support");
        return nullptr;
    }
    
    // 获取填充模式
    int padding = napi_utils::get_int32_from_napi_value(env, args[3]);
    LOGI("padding: %{public}d", padding);
    EVP_CIPHER_CTX_set_padding(ctx, padding);
    
    // 获取input并解密
    size_t inl = 0;
    unsigned char* inputPtr = napi_utils::get_arraybuffer_from_napi_value(env, args[4], &inl);
    
    // 创建input的副本（使用安全内存操作）
    unsigned char* input = new unsigned char[inl];
    if (memcpy_s(input, inl, inputPtr, inl) != EOK) {
        delete[] key;
        delete[] iv;
        delete[] input;
        EVP_CIPHER_CTX_free(ctx);
        napi_throw_error(env, nullptr, "Failed to copy input");
        return nullptr;
    }
    
    LOGI("input length: %{public}zu", inl);

    if (input == nullptr || inl == 0) {
        delete[] key;
        delete[] iv;
        delete[] input;
        EVP_CIPHER_CTX_free(ctx);
        napi_throw_error(env, nullptr, "input is empty");
        return nullptr;
    }
    
    // 获取块大小
    int blockSize = EVP_CIPHER_CTX_block_size(ctx);
    // 当关闭填充时，检查输入长度是否是块大小的整数倍
    if (padding == 0 && (inl % blockSize != 0)) {
        delete[] key;
        delete[] iv;
        delete[] input;
        EVP_CIPHER_CTX_free(ctx);
        std::string errMsg = "When padding is disabled, input length (" + std::to_string(inl) + 
                            ") must be a multiple of block size (" + std::to_string(blockSize) + ")";
        LOGE("%{public}s", errMsg.c_str());
        napi_throw_error(env, nullptr, errMsg.c_str());
        return nullptr;
    }
    
    // 分配输出缓冲区(需要比输入大,至少 inl + block_size)
    size_t maxOutLen = inl + blockSize;
    unsigned char* out = new unsigned char[maxOutLen];
    memset(out, 0, maxOutLen);  // 初始化为0，避免垃圾数据
    int outl = 0;
    int cipherLen = 0;  // 初始化为0
    
    if (EVP_DecryptUpdate(ctx, out, &outl, input, (int)inl) != 1){
        ERR_print_errors_cb(openssl_error_callback, nullptr);
        delete[] key;
        delete[] iv;
        delete[] input;
        delete[] out;
        EVP_CIPHER_CTX_free(ctx);
        napi_throw_error(env, nullptr, "EVP_EncryptUpdate failed");
        return nullptr;
    }
    cipherLen += outl;
    
    if (EVP_DecryptFinal_ex(ctx, out + outl, &outl) != 1){
        ERR_print_errors_cb(openssl_error_callback, nullptr);
        delete[] key;
        delete[] iv;
        delete[] input;
        delete[] out;
        EVP_CIPHER_CTX_free(ctx);
        napi_throw_error(env, nullptr, "EVP_EncryptFinal_ex failed");
        return nullptr;
    }
    cipherLen += outl;
    LOGI("cipherLen: %{public}d", cipherLen);
    
    // 清理资源
    EVP_CIPHER_CTX_free(ctx);
    delete[] key;
    delete[] iv;
    delete[] input;
    
    // 创建返回的 ArrayBuffer
    napi_value arraybuffer;
    void* buffer_data = nullptr;
    napi_status status = napi_create_arraybuffer(env, cipherLen, &buffer_data, &arraybuffer);
    if (status != napi_ok || buffer_data == nullptr) {
        delete[] out;
        napi_throw_error(env, nullptr, "napi_create_arraybuffer failed");
        return nullptr;
    }
    
    // 复制加密数据
    int ret = memcpy_s(buffer_data, cipherLen, out, cipherLen);
    delete[] out;  // 释放临时缓冲区
    
    if (ret != EOK) {
        LOGE("memcpy_s failed, ret = %{public}d", ret);
        napi_throw_error(env, nullptr, "memcpy_s failed");
        return nullptr;
    }
    
    return arraybuffer;
}

EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        { "encrypt", nullptr, Encrypt, nullptr, nullptr, nullptr, napi_default, nullptr },
        { "decrypt", nullptr, Decrypt, nullptr, nullptr, nullptr, napi_default, nullptr },
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}
EXTERN_C_END

static napi_module demoModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "hmcrypto",
    .nm_priv = ((void*)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void RegisterHMcryptoModule(void)
{
    napi_module_register(&demoModule);
}