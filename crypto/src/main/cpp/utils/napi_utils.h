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

#ifndef MQTT_OPENHARMONY_NAPI_UTILS_H
#define MQTT_OPENHARMONY_NAPI_UTILS_H

#include <string>
#include "napi/native_api.h"
namespace napi_utils {
    std::string get_string_from_napi_value(napi_env env, napi_value value);
    int32_t get_int32_from_napi_value(napi_env env, napi_value value);
    int64_t get_int64_from_napi_value(napi_env env, napi_value value);
    bool get_bool_from_napi_value(napi_env env, napi_value value);
    napi_value get_named_property_from_napi_value(napi_env env, napi_value object, const std::string &name);
    napi_value create_string_for_napi_value(napi_env env, const std::string &str);
    napi_value create_undefined_for_napi_value(napi_env env);
    int32_t get_int32_from_named_property(napi_env env, napi_value object, const std::string &name);
    int64_t get_int64_from_named_property(napi_env env, napi_value object, const std::string &name);
    std::string get_string_from_named_property(napi_env env, napi_value object, const std::string &name);
    bool get_bool_from_named_property(napi_env env, napi_value object, const std::string &name);
}
#endif //MQTT_OPENHARMONY_NAPI_UTILS_H
