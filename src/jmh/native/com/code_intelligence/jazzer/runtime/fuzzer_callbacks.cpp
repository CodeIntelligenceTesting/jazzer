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

#include <jni.h>

#include <cstddef>
#include <cstdint>

#include "com_code_intelligence_jazzer_runtime_FuzzerCallbacks.h"
#include "com_code_intelligence_jazzer_runtime_FuzzerCallbacksOptimizedCritical.h"
#include "com_code_intelligence_jazzer_runtime_FuzzerCallbacksOptimizedNonCritical.h"
#include "com_code_intelligence_jazzer_runtime_FuzzerCallbacksWithPc.h"
#include "src/main/native/com/code_intelligence/jazzer/driver/sanitizer_hooks_with_pc.h"

extern "C" {
void __sanitizer_weak_hook_compare_bytes(void *caller_pc, const void *s1,
                                         const void *s2, std::size_t n1,
                                         std::size_t n2, int result);
void __sanitizer_weak_hook_strstr(void *caller_pc, const char *s1,
                                  const char *s2, const char *result);
void __sanitizer_weak_hook_memmem(void *caller_pc, const void *b1,
                                  std::size_t n1, const void *s2,
                                  std::size_t n2, void *result);
void __sanitizer_cov_trace_cmp4(uint32_t arg1, uint32_t arg2);
void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2);

void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases);

void __sanitizer_cov_trace_div4(uint32_t val);
void __sanitizer_cov_trace_div8(uint64_t val);

void __sanitizer_cov_trace_gep(uintptr_t idx);
}

inline __attribute__((always_inline)) void *idToPc(jint id) {
  return reinterpret_cast<void *>(static_cast<uintptr_t>(id));
}

void Java_com_code_1intelligence_jazzer_runtime_FuzzerCallbacks_traceCmpInt(
    JNIEnv *env, jclass cls, jint value1, jint value2, jint id) {
  __sanitizer_cov_trace_cmp4(value1, value2);
}

void Java_com_code_1intelligence_jazzer_runtime_FuzzerCallbacksWithPc_traceCmpInt(
    JNIEnv *env, jclass cls, jint value1, jint value2, jint id) {
  __sanitizer_cov_trace_cmp4_with_pc(idToPc(id), value1, value2);
}

void Java_com_code_1intelligence_jazzer_runtime_FuzzerCallbacksOptimizedCritical_traceCmpInt(
    JNIEnv *env, jclass cls, jint value1, jint value2, jint id) {
  __sanitizer_cov_trace_cmp4(value1, value2);
}

extern "C" JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_FuzzerCallbacksOptimizedCritical_traceCmpInt(
    jint value1, jint value2, jint id) {
  __sanitizer_cov_trace_cmp4(value1, value2);
}

void Java_com_code_1intelligence_jazzer_runtime_FuzzerCallbacks_traceSwitch(
    JNIEnv *env, jclass cls, jlong switch_value,
    jlongArray libfuzzer_case_values, jint id) {
  jlong *case_values =
      env->GetLongArrayElements(libfuzzer_case_values, nullptr);
  if (env->ExceptionCheck()) env->ExceptionDescribe();
  __sanitizer_cov_trace_switch(switch_value,
                               reinterpret_cast<uint64_t *>(case_values));
  env->ReleaseLongArrayElements(libfuzzer_case_values, case_values, JNI_ABORT);
  if (env->ExceptionCheck()) env->ExceptionDescribe();
}

void Java_com_code_1intelligence_jazzer_runtime_FuzzerCallbacksOptimizedNonCritical_traceSwitch(
    JNIEnv *env, jclass cls, jlong switch_value,
    jlongArray libfuzzer_case_values, jint id) {
  auto *case_values = static_cast<jlong *>(
      env->GetPrimitiveArrayCritical(libfuzzer_case_values, nullptr));
  __sanitizer_cov_trace_switch(switch_value,
                               reinterpret_cast<uint64_t *>(case_values));
  env->ReleasePrimitiveArrayCritical(libfuzzer_case_values, case_values,
                                     JNI_ABORT);
}

void Java_com_code_1intelligence_jazzer_runtime_FuzzerCallbacksWithPc_traceSwitch(
    JNIEnv *env, jclass cls, jlong switch_value,
    jlongArray libfuzzer_case_values, jint id) {
  jlong *case_values =
      env->GetLongArrayElements(libfuzzer_case_values, nullptr);
  if (env->ExceptionCheck()) env->ExceptionDescribe();
  __sanitizer_cov_trace_switch_with_pc(
      idToPc(id), switch_value, reinterpret_cast<uint64_t *>(case_values));
  env->ReleaseLongArrayElements(libfuzzer_case_values, case_values, JNI_ABORT);
  if (env->ExceptionCheck()) env->ExceptionDescribe();
}

void Java_com_code_1intelligence_jazzer_runtime_FuzzerCallbacksOptimizedCritical_traceSwitch(
    JNIEnv *env, jclass cls, jlong switch_value,
    jlongArray libfuzzer_case_values, jint id) {
  Java_com_code_1intelligence_jazzer_runtime_FuzzerCallbacksOptimizedNonCritical_traceSwitch(
      env, cls, switch_value, libfuzzer_case_values, id);
}

extern "C" JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_FuzzerCallbacksOptimizedCritical_traceSwitch(
    jlong switch_value, jint case_values_length, jlong *case_values, jint id) {
  __sanitizer_cov_trace_switch(switch_value,
                               reinterpret_cast<uint64_t *>(case_values));
}

void Java_com_code_1intelligence_jazzer_runtime_FuzzerCallbacks_traceMemcmp(
    JNIEnv *env, jclass cls, jbyteArray b1, jbyteArray b2, jint result,
    jint id) {
  jbyte *b1_native = env->GetByteArrayElements(b1, nullptr);
  if (env->ExceptionCheck()) env->ExceptionDescribe();
  jbyte *b2_native = env->GetByteArrayElements(b2, nullptr);
  if (env->ExceptionCheck()) env->ExceptionDescribe();
  jint b1_length = env->GetArrayLength(b1);
  if (env->ExceptionCheck()) env->ExceptionDescribe();
  jint b2_length = env->GetArrayLength(b2);
  if (env->ExceptionCheck()) env->ExceptionDescribe();
  __sanitizer_weak_hook_compare_bytes(idToPc(id), b1_native, b2_native,
                                      b1_length, b2_length, result);
  env->ReleaseByteArrayElements(b1, b1_native, JNI_ABORT);
  if (env->ExceptionCheck()) env->ExceptionDescribe();
  env->ReleaseByteArrayElements(b2, b2_native, JNI_ABORT);
  if (env->ExceptionCheck()) env->ExceptionDescribe();
}

void Java_com_code_1intelligence_jazzer_runtime_FuzzerCallbacksOptimizedNonCritical_traceMemcmp(
    JNIEnv *env, jclass cls, jbyteArray b1, jbyteArray b2, jint result,
    jint id) {
  auto *b1_native =
      static_cast<jbyte *>(env->GetPrimitiveArrayCritical(b1, nullptr));
  auto *b2_native =
      static_cast<jbyte *>(env->GetPrimitiveArrayCritical(b2, nullptr));
  jint b1_length = env->GetArrayLength(b1);
  jint b2_length = env->GetArrayLength(b2);
  __sanitizer_weak_hook_compare_bytes(idToPc(id), b1_native, b2_native,
                                      b1_length, b2_length, result);
  env->ReleasePrimitiveArrayCritical(b1, b1_native, JNI_ABORT);
  env->ReleasePrimitiveArrayCritical(b2, b2_native, JNI_ABORT);
}

void Java_com_code_1intelligence_jazzer_runtime_FuzzerCallbacksOptimizedCritical_traceMemcmp(
    JNIEnv *env, jclass cls, jbyteArray b1, jbyteArray b2, jint result,
    jint id) {
  Java_com_code_1intelligence_jazzer_runtime_FuzzerCallbacksOptimizedNonCritical_traceMemcmp(
      env, cls, b1, b2, result, id);
}

extern "C" JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_FuzzerCallbacksOptimizedCritical_traceMemcmp(
    jint b1_length, jbyte *b1, jint b2_length, jbyte *b2, jint result,
    jint id) {
  __sanitizer_weak_hook_compare_bytes(idToPc(id), b1, b2, b1_length, b2_length,
                                      result);
}

void Java_com_code_1intelligence_jazzer_runtime_FuzzerCallbacks_traceStrstr(
    JNIEnv *env, jclass cls, jstring s1, jstring s2, jint id) {
  const char *s1_native = env->GetStringUTFChars(s1, nullptr);
  if (env->ExceptionCheck()) env->ExceptionDescribe();
  const char *s2_native = env->GetStringUTFChars(s2, nullptr);
  if (env->ExceptionCheck()) env->ExceptionDescribe();
  // libFuzzer currently ignores the result, which allows us to simply pass a
  // valid but arbitrary pointer here instead of performing an actual strstr
  // operation.
  __sanitizer_weak_hook_strstr(idToPc(id), s1_native, s2_native, s1_native);
  env->ReleaseStringUTFChars(s1, s1_native);
  if (env->ExceptionCheck()) env->ExceptionDescribe();
  env->ReleaseStringUTFChars(s2, s2_native);
  if (env->ExceptionCheck()) env->ExceptionDescribe();
}

void Java_com_code_1intelligence_jazzer_runtime_FuzzerCallbacksOptimizedNonCritical_traceStrstr(
    JNIEnv *env, jclass cls, jstring s1, jstring s2, jint id) {
  const char *s2_native = env->GetStringUTFChars(s2, nullptr);
  __sanitizer_weak_hook_strstr(idToPc(id), nullptr, s2_native, s2_native);
  env->ReleaseStringUTFChars(s2, s2_native);
}

void Java_com_code_1intelligence_jazzer_runtime_FuzzerCallbacksOptimizedNonCritical_traceStrstrInternal(
    JNIEnv *env, jclass cls, jbyteArray needle, jint id) {
  auto *needle_native =
      static_cast<jbyte *>(env->GetPrimitiveArrayCritical(needle, nullptr));
  jint needle_length = env->GetArrayLength(needle);
  __sanitizer_weak_hook_memmem(idToPc(id), nullptr, 0, needle_native,
                               needle_length, nullptr);
  env->ReleasePrimitiveArrayCritical(needle, needle_native, JNI_ABORT);
}

void Java_com_code_1intelligence_jazzer_runtime_FuzzerCallbacksOptimizedCritical_traceStrstrInternal(
    JNIEnv *env, jclass cls, jbyteArray needle, jint id) {
  Java_com_code_1intelligence_jazzer_runtime_FuzzerCallbacksOptimizedNonCritical_traceStrstrInternal(
      env, cls, needle, id);
}

extern "C" JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_FuzzerCallbacksOptimizedCritical_traceStrstrInternal(
    jint needle_length, jbyte *needle, jint id) {
  __sanitizer_weak_hook_memmem(idToPc(id), nullptr, 0, needle, needle_length,
                               nullptr);
}
