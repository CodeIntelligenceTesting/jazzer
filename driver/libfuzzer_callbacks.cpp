// Copyright 2021 Code Intelligence GmbH
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

#include "libfuzzer_callbacks.h"

#include <algorithm>
#include <iostream>

#include "absl/strings/str_format.h"
#include "glog/logging.h"
#include "sanitizer_hooks_with_pc.h"
#include "third_party/jni/jni.h"

DEFINE_bool(
    fake_pcs, false,
    "Supply synthetic Java program counters to libFuzzer trace hooks to "
    "make value profiling more effective. Enabled by default if "
    "-use_value_profile=1 is specified.");

namespace {

const char kLibfuzzerTraceDataFlowHooksClass[] =
    "com/code_intelligence/jazzer/runtime/"
    "TraceDataFlowNativeCallbacks";

extern "C" {
void __sanitizer_weak_hook_memcmp(void *caller_pc, const void *s1,
                                  const void *s2, std::size_t n, int result);
void __sanitizer_weak_hook_strcmp(void *caller_pc, const char *s1,
                                  const char *s2, int result);
void __sanitizer_weak_hook_strstr(void *caller_pc, const char *s1,
                                  const char *s2, const char *result);
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

void JNICALL libfuzzerStringCompareCallback(JNIEnv &env, jclass cls, jstring s1,
                                            jstring s2, jint result, jint id) {
  const char *s1_native = env.GetStringUTFChars(s1, nullptr);
  const char *s2_native = env.GetStringUTFChars(s2, nullptr);
  env.ExceptionDescribe();
  __sanitizer_weak_hook_strcmp(idToPc(id), s1_native, s2_native, result);
  env.ReleaseStringUTFChars(s1, s1_native);
  env.ReleaseStringUTFChars(s2, s2_native);
  env.ExceptionDescribe();
}

void JNICALL libfuzzerStringContainCallback(JNIEnv &env, jclass cls, jstring s1,
                                            jstring s2, jint id) {
  const char *s1_native = env.GetStringUTFChars(s1, nullptr);
  const char *s2_native = env.GetStringUTFChars(s2, nullptr);
  env.ExceptionDescribe();
  // libFuzzer currently ignores the result, which allows us to simply pass a
  // valid but arbitrary pointer here instead of performing an actual strstr
  // operation.
  __sanitizer_weak_hook_strstr(idToPc(id), s1_native, s2_native, s1_native);
  env.ReleaseStringUTFChars(s1, s1_native);
  env.ReleaseStringUTFChars(s2, s2_native);
  env.ExceptionDescribe();
}

void JNICALL libfuzzerByteCompareCallback(JNIEnv &env, jclass cls,
                                          jbyteArray b1, jint b1_length,
                                          jbyteArray b2, jint b2_length,
                                          jint result, jint id) {
  jbyte *b1_native = env.GetByteArrayElements(b1, nullptr);
  jbyte *b2_native = env.GetByteArrayElements(b2, nullptr);
  env.ExceptionDescribe();
  __sanitizer_weak_hook_memcmp(idToPc(id), b1_native, b2_native,
                               std::min(b1_length, b2_length), result);
  env.ReleaseByteArrayElements(b1, b1_native, JNI_ABORT);
  env.ReleaseByteArrayElements(b2, b2_native, JNI_ABORT);
  env.ExceptionDescribe();
}

void JNICALL libfuzzerLongCompareCallback(JNIEnv &env, jclass cls, jlong value1,
                                          jlong value2, jint id) {
  __sanitizer_cov_trace_cmp8(value1, value2);
}

void JNICALL libfuzzerLongCompareCallbackWithPc(JNIEnv &env, jclass cls,
                                                jlong value1, jlong value2,
                                                jint id) {
  __sanitizer_cov_trace_cmp8_with_pc(idToPc(id), value1, value2);
}

void JNICALL libfuzzerIntCompareCallback(JNIEnv &env, jclass cls, jint value1,
                                         jint value2, jint id) {
  __sanitizer_cov_trace_cmp4(value1, value2);
}

void JNICALL libfuzzerIntCompareCallbackWithPc(JNIEnv &env, jclass cls,
                                               jint value1, jint value2,
                                               jint id) {
  __sanitizer_cov_trace_cmp4_with_pc(idToPc(id), value1, value2);
}

void JNICALL libfuzzerSwitchCaseCallback(JNIEnv &env, jclass cls,
                                         jlong switch_value,
                                         jlongArray libfuzzer_case_values,
                                         jint id) {
  jlong *case_values = env.GetLongArrayElements(libfuzzer_case_values, nullptr);
  __sanitizer_cov_trace_switch(switch_value,
                               reinterpret_cast<uint64_t *>(case_values));
  env.ReleaseLongArrayElements(libfuzzer_case_values, case_values, JNI_ABORT);
}

void JNICALL libfuzzerSwitchCaseCallbackWithPc(JNIEnv &env, jclass cls,
                                               jlong switch_value,
                                               jlongArray libfuzzer_case_values,
                                               jint id) {
  jlong *case_values = env.GetLongArrayElements(libfuzzer_case_values, nullptr);
  __sanitizer_cov_trace_switch_with_pc(
      idToPc(id), switch_value, reinterpret_cast<uint64_t *>(case_values));
  env.ReleaseLongArrayElements(libfuzzer_case_values, case_values, JNI_ABORT);
}

void JNICALL libfuzzerLongDivCallback(JNIEnv &env, jclass cls, jlong value,
                                      jint id) {
  __sanitizer_cov_trace_div8(value);
}

void JNICALL libfuzzerLongDivCallbackWithPc(JNIEnv &env, jclass cls,
                                            jlong value, jint id) {
  __sanitizer_cov_trace_div8_with_pc(idToPc(id), value);
}

void JNICALL libfuzzerIntDivCallback(JNIEnv &env, jclass cls, jint value,
                                     jint id) {
  __sanitizer_cov_trace_div4(value);
}

void JNICALL libfuzzerIntDivCallbackWithPc(JNIEnv &env, jclass cls, jint value,
                                           jint id) {
  __sanitizer_cov_trace_div4_with_pc(idToPc(id), value);
}

void JNICALL libfuzzerGepCallback(JNIEnv &env, jclass cls, jlong idx, jint id) {
  __sanitizer_cov_trace_gep(static_cast<uintptr_t>(idx));
}

void JNICALL libfuzzerGepCallbackWithPc(JNIEnv &env, jclass cls, jlong idx,
                                        jint id) {
  __sanitizer_cov_trace_gep_with_pc(idToPc(id), static_cast<uintptr_t>(idx));
}

void registerCallback(JNIEnv &env, const char *java_hooks_class_name,
                      const JNINativeMethod *methods, int num_methods) {
  auto java_hooks_class = env.FindClass(java_hooks_class_name);
  if (java_hooks_class == nullptr) {
    env.ExceptionDescribe();
    throw std::runtime_error(
        absl::StrFormat("could not find class %s", java_hooks_class_name));
  }
  LOG(INFO) << "registering hooks for class " << java_hooks_class_name;
  env.RegisterNatives(java_hooks_class, methods, num_methods);
  if (env.ExceptionCheck()) {
    env.ExceptionDescribe();
    throw std::runtime_error("could not register native callbacks");
  }
}
}  // namespace

namespace jazzer {

bool registerFuzzerCallbacks(JNIEnv &env) {
  if (FLAGS_fake_pcs) {
    LOG(INFO) << "using callback variants with fake pcs";
  }
  {
    JNINativeMethod string_methods[]{
        {(char *)"traceMemcmp", (char *)"([BI[BIII)V",
         (void *)&libfuzzerByteCompareCallback},
        {(char *)"traceStrcmp",
         (char *)"(Ljava/lang/String;Ljava/lang/String;II)V",
         (void *)&libfuzzerStringCompareCallback},
        {(char *)"traceStrstr",
         (char *)"(Ljava/lang/String;Ljava/lang/String;I)V",
         (void *)&libfuzzerStringContainCallback}};

    registerCallback(env, kLibfuzzerTraceDataFlowHooksClass, string_methods,
                     sizeof(string_methods) / sizeof(string_methods[0]));
  }

  {
    JNINativeMethod cmp_methods[]{
        {(char *)"traceCmpLong", (char *)"(JJI)V",
         (void *)(FLAGS_fake_pcs ? &libfuzzerLongCompareCallbackWithPc
                                 : &libfuzzerLongCompareCallback)},
        {(char *)"traceCmpInt", (char *)"(III)V",
         (void *)(FLAGS_fake_pcs ? &libfuzzerIntCompareCallbackWithPc
                                 : &libfuzzerIntCompareCallback)},
        // libFuzzer internally treats const comparisons the same as
        // non-constant cmps.
        {(char *)"traceConstCmpInt", (char *)"(III)V",
         (void *)(FLAGS_fake_pcs ? &libfuzzerIntCompareCallbackWithPc
                                 : &libfuzzerIntCompareCallback)},
        {(char *)"traceSwitch", (char *)"(J[JI)V",
         (void *)(FLAGS_fake_pcs ? &libfuzzerSwitchCaseCallbackWithPc
                                 : &libfuzzerSwitchCaseCallback)}};

    registerCallback(env, kLibfuzzerTraceDataFlowHooksClass, cmp_methods,
                     sizeof(cmp_methods) / sizeof(cmp_methods[0]));
  }

  {
    JNINativeMethod div_methods[]{
        {(char *)"traceDivLong", (char *)"(JI)V",
         (void *)(FLAGS_fake_pcs ? &libfuzzerLongDivCallbackWithPc
                                 : &libfuzzerLongDivCallback)},
        {(char *)"traceDivInt", (char *)"(II)V",
         (void *)(FLAGS_fake_pcs ? &libfuzzerIntDivCallbackWithPc
                                 : &libfuzzerIntDivCallback)}};

    registerCallback(env, kLibfuzzerTraceDataFlowHooksClass, div_methods,
                     sizeof(div_methods) / sizeof(div_methods[0]));
  }

  {
    JNINativeMethod gep_methods[]{
        {(char *)"traceGep", (char *)"(JI)V",
         (void *)(FLAGS_fake_pcs ? &libfuzzerGepCallbackWithPc
                                 : &libfuzzerGepCallback)}};

    registerCallback(env, kLibfuzzerTraceDataFlowHooksClass, gep_methods,
                     sizeof(gep_methods) / sizeof(gep_methods[0]));
  }

  return env.ExceptionCheck();
}

}  // namespace jazzer
