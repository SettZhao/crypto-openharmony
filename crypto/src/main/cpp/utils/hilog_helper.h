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

#ifndef HILOG_HELPER_H
#define HILOG_HELPER_H

#include <hilog/log.h>

#define MQTT_LOG_TAG "[mqtt]"
#define MQTT_LOG_DOMAIN 0x0000  // 自定义域ID


#define LOGD(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_DEBUG, MQTT_LOG_DOMAIN, MQTT_LOG_TAG, fmt, ##__VA_ARGS__)

#define LOGI(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_INFO, MQTT_LOG_DOMAIN, MQTT_LOG_TAG, fmt, ##__VA_ARGS__)

#define LOGW(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_WARN, MQTT_LOG_DOMAIN, MQTT_LOG_TAG, fmt, ##__VA_ARGS__)

#define LOGE(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_ERROR, MQTT_LOG_DOMAIN, MQTT_LOG_TAG, fmt, ##__VA_ARGS__)

#define LOGF(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_FATAL, MQTT_LOG_DOMAIN, MQTT_LOG_TAG, fmt, ##__VA_ARGS__)

// 带自定义标签的宏
#define LOGD_TAG(tag, fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_DEBUG, MQTT_LOG_DOMAIN, tag, fmt, ##__VA_ARGS__)

#define LOGI_TAG(tag, fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_INFO, MQTT_LOG_DOMAIN, tag, fmt, ##__VA_ARGS__)

#define LOGW_TAG(tag, fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_WARN, MQTT_LOG_DOMAIN, tag, fmt, ##__VA_ARGS__)

#define LOGE_TAG(tag, fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_ERROR, MQTT_LOG_DOMAIN, tag, fmt, ##__VA_ARGS__)

#define LOGF_TAG(tag, fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_FATAL, MQTT_LOG_DOMAIN, tag, fmt, ##__VA_ARGS__)

#endif // HILOG_HELPER_H
