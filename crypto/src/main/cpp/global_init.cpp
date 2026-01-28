//
// Created on 2026/1/26.
//
// Node APIs are not fully supported. To solve the compilation error of the interface cannot be found,
// please include "napi/native_api.h".

#include "global_init.h"
#include "openssl/types.h"
#include "openssl/provider.h"
#include "openssl/err.h"
#include "utils/hilog_helper.h"
#include <mutex>
// 全局 provider 指针和互斥锁
static std::once_flag init_flag;
static OSSL_PROVIDER *legacy_provider = nullptr;
static OSSL_PROVIDER *default_provider = nullptr;

int global_init::openssl_error_callback(const char *str, size_t len, void *u) {
    LOGE("openssl error: %{public}s", str);
    return 0;
}

bool global_init::globalInit() {
    std::call_once(init_flag, []() {
        // 先加载 default provider，再加载 legacy provider
        default_provider = OSSL_PROVIDER_load(nullptr, "default");
        if (default_provider == nullptr) {
            ERR_print_errors_cb(global_init::openssl_error_callback, nullptr);
            LOGE("OSSL_PROVIDER_load default failed");
        }

        legacy_provider = OSSL_PROVIDER_load(nullptr, "legacy");
        if (legacy_provider == nullptr) {
            ERR_print_errors_cb(global_init::openssl_error_callback, nullptr);
            LOGE("OSSL_PROVIDER_load legacy failed");
            throw std::runtime_error("Failed to load legacy provider");
        }
        LOGI("OpenSSL providers loaded successfully");
    });
    return true;
}