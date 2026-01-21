cmake_minimum_required(VERSION 3.5)

# ✅ 只保留一个顶层 project() 命令
project(crypto_thirdparty)

set(can_use_assembler TRUE)
enable_language(ASM)
IF("${OHOS_ARCH}" STREQUAL "arm64-v8a")
 SET(ASM_OPTIONS "-x assembler-with-cpp")
 SET(CMAKE_ASM_FLAGS "${CFLAGS} ${ASM_OPTIONS} -march=armv8+crypto -D__OHOS__")
ENDIF()

# ==================== boundscheck 安全库 ====================
message(STATUS "Building boundscheck library...")
set(TAGET_BOUNDSCHECK_SRC_PATH ${CMAKE_CURRENT_SOURCE_DIR}/libboundscheck/src)
set(SECUREC_ENABLE_VSPRINTF 1)
set(SECUREC_ENABLE_SNPRINTF 1)
add_library(boundscheck
            STATIC
            ${TAGET_BOUNDSCHECK_SRC_PATH}/memcpy_s.c
            ${TAGET_BOUNDSCHECK_SRC_PATH}/memset_s.c
            ${TAGET_BOUNDSCHECK_SRC_PATH}/memmove_s.c
            ${TAGET_BOUNDSCHECK_SRC_PATH}/vsprintf_s.c
            ${TAGET_BOUNDSCHECK_SRC_PATH}/sprintf_s.c
            ${TAGET_BOUNDSCHECK_SRC_PATH}/vsnprintf_s.c
            ${TAGET_BOUNDSCHECK_SRC_PATH}/secureprintoutput_a.c
            ${TAGET_BOUNDSCHECK_SRC_PATH}/snprintf_s.c
            ${TAGET_BOUNDSCHECK_SRC_PATH}/securecutil.c)
include_directories(${TAGET_BOUNDSCHECK_SRC_PATH}
                    ${CMAKE_CURRENT_SOURCE_DIR}/libboundscheck/include)