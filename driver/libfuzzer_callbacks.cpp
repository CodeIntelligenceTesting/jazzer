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

#include <jni.h>

#include <fstream>
#include <iostream>
#include <mutex>
#include <utility>
#include <vector>

#include "absl/strings/match.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_split.h"
#include "gflags/gflags.h"
#include "glog/logging.h"
#include "sanitizer_hooks_with_pc.h"

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
void __sanitizer_weak_hook_compare_bytes(void *caller_pc, const void *s1,
                                         const void *s2, std::size_t n1,
                                         std::size_t n2, int result);
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
  if (env.ExceptionCheck()) env.ExceptionDescribe();
  std::size_t n1 = env.GetStringUTFLength(s1);
  if (env.ExceptionCheck()) env.ExceptionDescribe();
  const char *s2_native = env.GetStringUTFChars(s2, nullptr);
  if (env.ExceptionCheck()) env.ExceptionDescribe();
  std::size_t n2 = env.GetStringUTFLength(s2);
  if (env.ExceptionCheck()) env.ExceptionDescribe();
  __sanitizer_weak_hook_compare_bytes(idToPc(id), s1_native, s2_native, n1, n2,
                                      result);
  env.ReleaseStringUTFChars(s1, s1_native);
  if (env.ExceptionCheck()) env.ExceptionDescribe();
  env.ReleaseStringUTFChars(s2, s2_native);
  if (env.ExceptionCheck()) env.ExceptionDescribe();
}

void JNICALL libfuzzerStringContainCallback(JNIEnv &env, jclass cls, jstring s1,
                                            jstring s2, jint id) {
  const char *s1_native = env.GetStringUTFChars(s1, nullptr);
  if (env.ExceptionCheck()) env.ExceptionDescribe();
  const char *s2_native = env.GetStringUTFChars(s2, nullptr);
  if (env.ExceptionCheck()) env.ExceptionDescribe();
  // libFuzzer currently ignores the result, which allows us to simply pass a
  // valid but arbitrary pointer here instead of performing an actual strstr
  // operation.
  __sanitizer_weak_hook_strstr(idToPc(id), s1_native, s2_native, s1_native);
  env.ReleaseStringUTFChars(s1, s1_native);
  if (env.ExceptionCheck()) env.ExceptionDescribe();
  env.ReleaseStringUTFChars(s2, s2_native);
  if (env.ExceptionCheck()) env.ExceptionDescribe();
}

void JNICALL libfuzzerByteCompareCallback(JNIEnv &env, jclass cls,
                                          jbyteArray b1, jbyteArray b2,
                                          jint result, jint id) {
  jbyte *b1_native = env.GetByteArrayElements(b1, nullptr);
  if (env.ExceptionCheck()) env.ExceptionDescribe();
  jbyte *b2_native = env.GetByteArrayElements(b2, nullptr);
  if (env.ExceptionCheck()) env.ExceptionDescribe();
  jint b1_length = env.GetArrayLength(b1);
  if (env.ExceptionCheck()) env.ExceptionDescribe();
  jint b2_length = env.GetArrayLength(b2);
  if (env.ExceptionCheck()) env.ExceptionDescribe();
  __sanitizer_weak_hook_compare_bytes(idToPc(id), b1_native, b2_native,
                                      b1_length, b2_length, result);
  env.ReleaseByteArrayElements(b1, b1_native, JNI_ABORT);
  if (env.ExceptionCheck()) env.ExceptionDescribe();
  env.ReleaseByteArrayElements(b2, b2_native, JNI_ABORT);
  if (env.ExceptionCheck()) env.ExceptionDescribe();
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
  if (env.ExceptionCheck()) env.ExceptionDescribe();
  __sanitizer_cov_trace_switch(switch_value,
                               reinterpret_cast<uint64_t *>(case_values));
  env.ReleaseLongArrayElements(libfuzzer_case_values, case_values, JNI_ABORT);
  if (env.ExceptionCheck()) env.ExceptionDescribe();
}

void JNICALL libfuzzerSwitchCaseCallbackWithPc(JNIEnv &env, jclass cls,
                                               jlong switch_value,
                                               jlongArray libfuzzer_case_values,
                                               jint id) {
  jlong *case_values = env.GetLongArrayElements(libfuzzer_case_values, nullptr);
  if (env.ExceptionCheck()) env.ExceptionDescribe();
  __sanitizer_cov_trace_switch_with_pc(
      idToPc(id), switch_value, reinterpret_cast<uint64_t *>(case_values));
  env.ReleaseLongArrayElements(libfuzzer_case_values, case_values, JNI_ABORT);
  if (env.ExceptionCheck()) env.ExceptionDescribe();
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

void JNICALL libfuzzerPcIndirCallback(JNIEnv &env, jclass cls, jint caller_id,
                                      jint callee_id) {
  __sanitizer_cov_trace_pc_indir_with_pc(idToPc(caller_id),
                                         static_cast<uintptr_t>(callee_id));
}

bool is_using_native_libraries = false;
std::once_flag ignore_list_flag;
std::vector<std::pair<uintptr_t, uintptr_t>> ignore_for_interception_ranges;

extern "C" [[maybe_unused]] bool __sanitizer_weak_is_relevant_pc(
    void *caller_pc) {
  // If the fuzz target is not using native libraries, calls to strcmp, memcmp,
  // etc. should never be intercepted. The values reported if they were at best
  // duplicate the values received from our bytecode instrumentation and at
  // worst pollute the table of recent compares with string internal to the JDK.
  if (!is_using_native_libraries) return false;
  // If the fuzz target is using native libraries, intercept calls only if they
  // don't originate from those address ranges that are known to belong to the
  // JDK.
  return std::none_of(ignore_for_interception_ranges.cbegin(),
                      ignore_for_interception_ranges.cend(),
                      [caller_pc](const auto &range) {
                        uintptr_t start;
                        uintptr_t end;
                        std::tie(start, end) = range;
                        auto address = reinterpret_cast<uintptr_t>(caller_pc);
                        return start <= address && address <= end;
                      });
}

/**
 * Adds the address ranges of executable segmentes of the library lib_name to
 * the ignorelist for C standard library function interception (strcmp, memcmp,
 * ...).
 */
void ignoreLibraryForInterception(const std::string &lib_name) {
  const auto num_address_ranges = ignore_for_interception_ranges.size();
  std::ifstream loaded_libs("/proc/self/maps");
  if (!loaded_libs) {
    // This early exit is taken e.g. on macOS, where /proc does not exist.
    return;
  }
  std::string line;
  while (std::getline(loaded_libs, line)) {
    if (!absl::StrContains(line, lib_name)) continue;
    // clang-format off
    // A typical line looks as follows:
    // 7f15356c9000-7f1536367000 r-xp 0020d000 fd:01 19275673         /usr/lib/jvm/java-15-openjdk-amd64/lib/server/libjvm.so
    // clang-format on
    std::vector<std::string_view> parts =
        absl::StrSplit(line, ' ', absl::SkipEmpty());
    if (parts.size() != 6) {
      std::cout << "ERROR: Invalid format for /proc/self/maps\n"
                << line << std::endl;
      exit(1);
    }
    // Skip non-executable address rang"s.
    if (!absl::StrContains(parts[1], "x")) continue;
    std::string_view range_str = parts[0];
    std::vector<std::string> range = absl::StrSplit(range_str, "-");
    if (range.size() != 2) {
      std::cout
          << "ERROR: Unexpected address range format in /proc/self/maps line: "
          << range_str << std::endl;
      exit(1);
    }
    std::size_t pos;
    auto start = std::stoull(range[0], &pos, 16);
    if (pos != range[0].size()) {
      std::cout
          << "ERROR: Unexpected address range format in /proc/self/maps line: "
          << range_str << std::endl;
      exit(1);
    }
    auto end = std::stoull(range[1], &pos, 16);
    if (pos != range[0].size()) {
      std::cout
          << "ERROR: Unexpected address range format in /proc/self/maps line: "
          << range_str << std::endl;
      exit(1);
    }
    ignore_for_interception_ranges.emplace_back(start, end);
  }
  const auto num_code_segments =
      ignore_for_interception_ranges.size() - num_address_ranges;
  LOG(INFO) << "added " << num_code_segments
            << " code segment of native library " << lib_name
            << " to interceptor ignorelist";
}

const std::vector<std::string> kLibrariesToIgnoreForInterception = {
    // The driver executable itself can be treated just like a library.
    "jazzer_driver", "libinstrument.so", "libjava.so",
    "libjimage.so",  "libjli.so",        "libjvm.so",
    "libnet.so",     "libverify.so",     "libzip.so",
};

void JNICALL handleLibraryLoad(JNIEnv &env, jclass cls) {
  std::call_once(ignore_list_flag, [] {
    LOG(INFO)
        << "detected a native library load, enabling interception for libc "
           "functions";
    for (const auto &lib_name : kLibrariesToIgnoreForInterception)
      ignoreLibraryForInterception(lib_name);
    // Enable the ignore list after it has been populated since vector is not
    // thread-safe with respect to concurrent writes and reads.
    is_using_native_libraries = true;
  });
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
    CalibrateTrampoline();
  }
  {
    JNINativeMethod string_methods[]{
        {(char *)"traceMemcmp", (char *)"([B[BII)V",
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

  {
    JNINativeMethod indir_methods[]{{(char *)"tracePcIndir", (char *)"(II)V",
                                     (void *)(&libfuzzerPcIndirCallback)}};

    registerCallback(env, kLibfuzzerTraceDataFlowHooksClass, indir_methods,
                     sizeof(indir_methods) / sizeof(indir_methods[0]));
  }

  {
    JNINativeMethod native_methods[]{{(char *)"handleLibraryLoad",
                                      (char *)"()V",
                                      (void *)(&handleLibraryLoad)}};

    registerCallback(env, kLibfuzzerTraceDataFlowHooksClass, native_methods,
                     sizeof(native_methods) / sizeof(native_methods[0]));
  }

  return env.ExceptionCheck();
}

}  // namespace jazzer
