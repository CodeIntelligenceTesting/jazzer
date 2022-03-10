// Copyright 2022 Code Intelligence GmbH
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

#include "com_code_intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks.h"
#include "driver/sanitizer_hooks_with_pc.h"

namespace {

extern "C" {
void __sanitizer_weak_hook_compare_bytes(void *caller_pc, const void *s1,
                                         const void *s2, std::size_t n1,
                                         std::size_t n2, int result);
void __sanitizer_weak_hook_memmem(void *called_pc, const void *s1, size_t len1,
                                  const void *s2, size_t len2, void *result);
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
}  // namespace

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceStrstr0(
    JNIEnv *env, jclass cls, jbyteArray needle, jint id) {
  auto *needle_native =
      static_cast<jbyte *>(env->GetPrimitiveArrayCritical(needle, nullptr));
  jint needle_length = env->GetArrayLength(needle);
  __sanitizer_weak_hook_memmem(idToPc(id), nullptr, 0, needle_native,
                               needle_length, nullptr);
  env->ReleasePrimitiveArrayCritical(needle, needle_native, JNI_ABORT);
}

extern "C" [[maybe_unused]] JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceStrstr0(
    jint needle_length, jbyte *needle_native, jint id) {
  __sanitizer_weak_hook_memmem(idToPc(id), nullptr, 0, needle_native,
                               needle_length, nullptr);
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceMemcmp(
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

extern "C" [[maybe_unused]] JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceMemcmp(
    jint b1_length, jbyte *b1, jint b2_length, jbyte *b2, jint result,
    jint id) {
  __sanitizer_weak_hook_compare_bytes(idToPc(id), b1, b2, b1_length, b2_length,
                                      result);
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceCmpLong(
    JNIEnv *env, jclass cls, jlong value1, jlong value2) {
  __sanitizer_cov_trace_cmp8(value1, value2);
}

extern "C" [[maybe_unused]] JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceCmpLong(
    jlong value1, jlong value2) {
  __sanitizer_cov_trace_cmp8(value1, value2);
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceCmpLongWithPc(
    JNIEnv *env, jclass cls, jlong value1, jlong value2, jint id) {
  __sanitizer_cov_trace_cmp8_with_pc(idToPc(id), value1, value2);
}

extern "C" [[maybe_unused]] JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceCmpLongWithPc(
    jlong value1, jlong value2, jint id) {
  __sanitizer_cov_trace_cmp8_with_pc(idToPc(id), value1, value2);
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceCmpInt(
    JNIEnv *env, jclass cls, jint value1, jint value2) {
  __sanitizer_cov_trace_cmp4(value1, value2);
}

extern "C" [[maybe_unused]] JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceCmpInt(
    jint value1, jint value2) {
  __sanitizer_cov_trace_cmp4(value1, value2);
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceCmpIntWithPc(
    JNIEnv *env, jclass cls, jint value1, jint value2, jint id) {
  __sanitizer_cov_trace_cmp4_with_pc(idToPc(id), value1, value2);
}

extern "C" [[maybe_unused]] JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceCmpIntWithPc(
    jint value1, jint value2, jint id) {
  __sanitizer_cov_trace_cmp4_with_pc(idToPc(id), value1, value2);
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceConstCmpInt(
    JNIEnv *env, jclass cls, jint value1, jint value2) {
  __sanitizer_cov_trace_cmp4(value1, value2);
}

extern "C" [[maybe_unused]] JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceConstCmpInt(
    jint value1, jint value2) {
  __sanitizer_cov_trace_cmp4(value1, value2);
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceConstCmpIntWithPc(
    JNIEnv *env, jclass cls, jint value1, jint value2, jint id) {
  __sanitizer_cov_trace_cmp4_with_pc(idToPc(id), value1, value2);
}

extern "C" [[maybe_unused]] JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceConstCmpIntWithPc(
    jint value1, jint value2, jint id) {
  __sanitizer_cov_trace_cmp4_with_pc(idToPc(id), value1, value2);
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceSwitch(
    JNIEnv *env, jclass cls, jlong switch_value,
    jlongArray libfuzzer_case_values) {
  auto *case_values = static_cast<jlong *>(
      env->GetPrimitiveArrayCritical(libfuzzer_case_values, nullptr));
  __sanitizer_cov_trace_switch(switch_value,
                               reinterpret_cast<uint64_t *>(case_values));
  env->ReleasePrimitiveArrayCritical(libfuzzer_case_values, case_values,
                                     JNI_ABORT);
}

extern "C" [[maybe_unused]] JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceSwitch(
    jlong switch_value, jint libfuzzer_case_values_length, jlong *case_values) {
  __sanitizer_cov_trace_switch(switch_value,
                               reinterpret_cast<uint64_t *>(case_values));
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceSwitchWithPc(
    JNIEnv *env, jclass cls, jlong switch_value,
    jlongArray libfuzzer_case_values, jint id) {
  auto *case_values = static_cast<jlong *>(
      env->GetPrimitiveArrayCritical(libfuzzer_case_values, nullptr));
  __sanitizer_cov_trace_switch_with_pc(
      idToPc(id), switch_value, reinterpret_cast<uint64_t *>(case_values));
  env->ReleasePrimitiveArrayCritical(libfuzzer_case_values, case_values,
                                     JNI_ABORT);
}

extern "C" [[maybe_unused]] JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceSwitchWithPc(
    jlong switch_value, jint libfuzzer_case_values_length, jlong *case_values,
    jint id) {
  __sanitizer_cov_trace_switch_with_pc(
      idToPc(id), switch_value, reinterpret_cast<uint64_t *>(case_values));
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceDivLong(
    JNIEnv *env, jclass cls, jlong value) {
  __sanitizer_cov_trace_div8(value);
}

extern "C" [[maybe_unused]] JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceDivLong(
    jlong value) {
  __sanitizer_cov_trace_div8(value);
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceDivLongWithPc(
    JNIEnv *env, jclass cls, jlong value, jint id) {
  __sanitizer_cov_trace_div8_with_pc(idToPc(id), value);
}

extern "C" [[maybe_unused]] JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceDivLongWithPc(
    jlong value, jint id) {
  __sanitizer_cov_trace_div8_with_pc(idToPc(id), value);
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceDivInt(
    JNIEnv *env, jclass cls, jint value) {
  __sanitizer_cov_trace_div4(value);
}

extern "C" [[maybe_unused]] JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceDivInt(
    jint value) {
  __sanitizer_cov_trace_div4(value);
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceDivIntWithPc(
    JNIEnv *env, jclass cls, jint value, jint id) {
  __sanitizer_cov_trace_div4_with_pc(idToPc(id), value);
}

extern "C" [[maybe_unused]] JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceDivIntWithPc(
    jint value, jint id) {
  __sanitizer_cov_trace_div4_with_pc(idToPc(id), value);
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceGep(
    JNIEnv *env, jclass cls, jlong idx) {
  __sanitizer_cov_trace_gep(static_cast<uintptr_t>(idx));
}

extern "C" [[maybe_unused]] JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceGep(
    jlong idx) {
  __sanitizer_cov_trace_gep(static_cast<uintptr_t>(idx));
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceGepWithPc(
    JNIEnv *env, jclass cls, jlong idx, jint id) {
  __sanitizer_cov_trace_gep_with_pc(idToPc(id), static_cast<uintptr_t>(idx));
}

extern "C" [[maybe_unused]] JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_traceGepWithPc(
    jlong idx, jint id) {
  __sanitizer_cov_trace_gep_with_pc(idToPc(id), static_cast<uintptr_t>(idx));
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_tracePcIndir0(
    JNIEnv *env, jclass cls, jint caller_id, jint callee_id) {
  __sanitizer_cov_trace_pc_indir_with_pc(idToPc(caller_id),
                                         static_cast<uintptr_t>(callee_id));
}

extern "C" [[maybe_unused]] JNIEXPORT void JNICALL
JavaCritical_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_tracePcIndir0(
    jint caller_id, jint callee_id) {
  __sanitizer_cov_trace_pc_indir_with_pc(idToPc(caller_id),
                                         static_cast<uintptr_t>(callee_id));
}
