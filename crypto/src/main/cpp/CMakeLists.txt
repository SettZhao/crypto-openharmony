# the minimum version of CMake.
cmake_minimum_required(VERSION 3.5.0)
project(hmcrypto)

set(NATIVERENDER_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")

# 添加Paho MQTT C库（开源的MQTT协议实现）
add_subdirectory(thirdparty)

add_library(hmcrypto SHARED napi_init.cpp
utils/hilog_helper.h
utils/hilog_helper.cpp
utils/napi_utils.h
utils/napi_utils.cpp
)

target_include_directories(hmcrypto PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/libboundscheck/include
)

target_link_libraries(hmcrypto PUBLIC
    libace_napi.z.so      # ACE NAPI库：提供JavaScript和C++交互的接口
    libhilog_ndk.z.so     # HiLog库：HarmonyOS的日志系统
    boundscheck           # ✅ 安全字符串库（用于mqtt wrapper中的安全函数调用）
    openssl
)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    # 去除符号表（减小文件大小）
    # -s: strip选项，移除调试符号
    target_link_options(hmcrypto PUBLIC -s)

    # 启用链接时优化（LTO: Link Time Optimization）
    # -flto=thin: 使用"瘦"LTO模式，在链接时进一步优化
    set(LTO_FLAG "-flto=thin")

    # 添加编译选项
    # -O3: 最高级别优化
    # 注意：-march=native 不适用于交叉编译，已移除
    add_compile_options(-O3)

    # 为mqtt目标添加特定的编译选项
    # PRIVATE: 只对mqtt本身有效
    target_compile_options(hmcrypto PRIVATE ${LTO_FLAG})

    # 为mqtt目标添加链接选项
    target_link_options(hmcrypto PRIVATE ${LTO_FLAG})
endif()
