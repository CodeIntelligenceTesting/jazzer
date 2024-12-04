// Copyright 2024 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstddef>
#include <cstdint>

#include "com_code_intelligence_jazzer_runtime_Mutator.h"

extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

[[maybe_unused]] jint
Java_com_code_1intelligence_jazzer_runtime_Mutator_defaultMutateNative(
    JNIEnv *env, jclass, jbyteArray jni_data, jint size) {
  jint maxSize = env->GetArrayLength(jni_data);
  uint8_t *data =
      static_cast<uint8_t *>(env->GetPrimitiveArrayCritical(jni_data, nullptr));
  jint res = LLVMFuzzerMutate(data, size, maxSize);
  env->ReleasePrimitiveArrayCritical(jni_data, data, 0);
  return res;
}
