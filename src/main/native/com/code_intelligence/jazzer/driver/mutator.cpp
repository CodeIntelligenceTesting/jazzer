// Copyright 2024 Code Intelligence GmbH
//
// By downloading, you agree to the Code Intelligence Jazzer Terms and
// Conditions.
//
// The Code Intelligence Jazzer Terms and Conditions are provided in
// LICENSE-JAZZER.txt located in the root directory of the project.

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
