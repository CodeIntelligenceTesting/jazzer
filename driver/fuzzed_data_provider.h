/*
 * Copyright 2021 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <jni.h>

#include <algorithm>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <iostream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace jazzer {

constexpr char kFuzzedDataProviderImplClass[] =
    "com/code_intelligence/jazzer/runtime/FuzzedDataProviderImpl";

// Registers the native methods in FuzzedDataProvider.
void SetUpFuzzedDataProvider(JNIEnv &env);

// Feed the FuzzedDataProvider with a new data buffer. The buffer is accessed
// by native code and not copied into the JVM, so this is cheap to call.
void FeedFuzzedDataProvider(const uint8_t *data, std::size_t size);
}  // namespace jazzer
