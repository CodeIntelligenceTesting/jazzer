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

/**
 * A native wrapper around the FuzzTargetRunner Java class that executes it as a
 * libFuzzer fuzz target.
 */

#include "fuzz_target_runner.h"

#include <jni.h>

#include <string>
#include <vector>

#include "absl/strings/str_format.h"
#include "com_code_intelligence_jazzer_driver_FuzzTargetRunner.h"
#include "driver/fuzzed_data_provider.h"
#include "gflags/gflags.h"

DEFINE_string(
    target_class, "",
    "The Java class that contains the static fuzzerTestOneInput function");
DEFINE_string(target_args, "",
              "Arguments passed to fuzzerInitialize as a String array. "
              "Separated by space.");

DEFINE_uint32(keep_going, 0,
              "Continue fuzzing until N distinct exception stack traces have"
              "been encountered. Defaults to exit after the first finding "
              "unless --autofuzz is specified.");
DEFINE_bool(dedup, true,
            "Emit a dedup token for every finding. Defaults to true and is "
            "required for --keep_going and --ignore.");
DEFINE_string(
    ignore, "",
    "Comma-separated list of crash dedup tokens to ignore. This is useful to "
    "continue fuzzing before a crash is fixed.");

DEFINE_string(reproducer_path, ".",
              "Path at which fuzzing reproducers are stored. Defaults to the "
              "current directory.");
DEFINE_string(coverage_report, "",
              "Path at which a coverage report is stored when the fuzzer "
              "exits. If left empty, no report is generated (default)");
DEFINE_string(coverage_dump, "",
              "Path at which a coverage dump is stored when the fuzzer "
              "exits. If left empty, no dump is generated (default)");

DEFINE_string(autofuzz, "",
              "Fully qualified reference to a method on the classpath that "
              "should be fuzzed automatically (example: System.out::println). "
              "Fuzzing will continue even after a finding; specify "
              "--keep_going=N to stop after N findings.");
DEFINE_string(autofuzz_ignore, "",
              "Fully qualified class names of exceptions to ignore during "
              "autofuzz. Separated by comma.");
DEFINE_bool(
    fake_pcs, false,
    "Supply synthetic Java program counters to libFuzzer trace hooks to "
    "make value profiling more effective. Enabled by default if "
    "-use_value_profile=1 is specified.");

DECLARE_bool(hooks);

extern "C" int LLVMFuzzerRunDriver(int *argc, char ***argv,
                                   int (*UserCb)(const uint8_t *Data,
                                                 size_t Size));

namespace {
constexpr auto kFuzzTargetRunnerClassName =
    "com/code_intelligence/jazzer/driver/FuzzTargetRunner";

bool gUseFuzzedDataProvider;
jclass gRunner;
jmethodID gRunOneId;
JNIEnv *gEnv;

// A libFuzzer-registered callback that outputs the crashing input, but does
// not include a stack trace.
void (*gLibfuzzerPrintCrashingInput)() = nullptr;

int testOneInput(const uint8_t *data, const std::size_t size) {
  JNIEnv &env = *gEnv;
  jbyteArray input = nullptr;
  jint jsize =
      std::min(size, static_cast<size_t>(std::numeric_limits<jint>::max()));
  if (gUseFuzzedDataProvider) {
    ::jazzer::FeedFuzzedDataProvider(data, size);
  } else {
    input = env.NewByteArray(jsize);
    env.SetByteArrayRegion(input, 0, jsize,
                           reinterpret_cast<const jbyte *>(data));
  }
  int res = env.CallStaticIntMethod(gRunner, gRunOneId, input);
  if (env.ExceptionCheck()) {
    env.ExceptionDescribe();
    _Exit(1);
  }
  return res;
}
}  // namespace

namespace jazzer {
std::vector<std::string> fuzzTargetRunnerFlagsAsDefines() {
  return {
      absl::StrFormat("-Djazzer.target_class=%s", FLAGS_target_class),
      absl::StrFormat("-Djazzer.target_args=%s", FLAGS_target_args),
      absl::StrFormat("-Djazzer.keep_going=%d", FLAGS_keep_going),
      absl::StrFormat("-Djazzer.dedup=%s", FLAGS_dedup ? "true" : "false"),
      absl::StrFormat("-Djazzer.ignore=%s", FLAGS_ignore),
      absl::StrFormat("-Djazzer.reproducer_path=%s", FLAGS_reproducer_path),
      absl::StrFormat("-Djazzer.coverage_report=%s", FLAGS_coverage_report),
      absl::StrFormat("-Djazzer.coverage_dump=%s", FLAGS_coverage_dump),
      absl::StrFormat("-Djazzer.autofuzz=%s", FLAGS_autofuzz),
      absl::StrFormat("-Djazzer.autofuzz_ignore=%s", FLAGS_autofuzz_ignore),
      absl::StrFormat("-Djazzer.hooks=%s", FLAGS_hooks ? "true" : "false"),
      absl::StrFormat("-Djazzer.fake_pcs=%s",
                      FLAGS_fake_pcs ? "true" : "false"),
  };
}

int StartFuzzer(JNIEnv *env, int argc, char **argv) {
  gEnv = env;
  jclass runner = env->FindClass(kFuzzTargetRunnerClassName);
  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    _Exit(1);
  }
  gRunner = reinterpret_cast<jclass>(env->NewGlobalRef(runner));
  gRunOneId = env->GetStaticMethodID(runner, "runOne", "([B)I");
  jfieldID use_fuzzed_data_provider_id =
      env->GetStaticFieldID(runner, "useFuzzedDataProvider", "Z");
  gUseFuzzedDataProvider =
      env->GetStaticBooleanField(runner, use_fuzzed_data_provider_id);

  return LLVMFuzzerRunDriver(&argc, &argv, testOneInput);
}

void DumpJvmStackTraces() {
  JavaVM *vm;
  jsize num_vms;
  JNI_GetCreatedJavaVMs(&vm, 1, &num_vms);
  if (num_vms != 1) {
    return;
  }
  JNIEnv *env = nullptr;
  if (vm->AttachCurrentThread(reinterpret_cast<void **>(&env), nullptr) !=
      JNI_OK) {
    return;
  }
  jmethodID dumpStack =
      env->GetStaticMethodID(gRunner, "dumpAllStackTraces", "()V");
  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    return;
  }
  env->CallStaticVoidMethod(gRunner, dumpStack);
  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    return;
  }
  // Do not detach as we may be the main thread (but the JVM exits anyway).
}
}  // namespace jazzer

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_driver_FuzzTargetRunner_printCrashingInput(
    JNIEnv *, jclass) {
  gLibfuzzerPrintCrashingInput();
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_driver_FuzzTargetRunner__1Exit(
    JNIEnv *, jclass, jint exit_code) {
  _Exit(exit_code);
}

// This symbol is defined by sanitizers if linked into Jazzer or in
// sanitizer_symbols.cpp if no sanitizer is used.
extern "C" void __sanitizer_set_death_callback(void (*)());

// We apply a patch to libFuzzer to make it call this function instead of
// __sanitizer_set_death_callback to pass us the death callback.
extern "C" [[maybe_unused]] void __jazzer_set_death_callback(
    void (*callback)()) {
  gLibfuzzerPrintCrashingInput = callback;
  __sanitizer_set_death_callback([]() {
    ::jazzer::DumpJvmStackTraces();
    gLibfuzzerPrintCrashingInput();
    // Ideally, we would be able to call driver_cleanup here to perform a
    // graceful shutdown of the JVM. However, doing this directly results in a
    // nested bug report by ASan or UBSan, likely because something about the
    // stack/thread context in which they generate reports is incompatible with
    // the JVM shutdown process. use_sigaltstack=0 does not help though, so this
    // might be on us. The alternative of calling driver_cleanup in a new thread
    // and joining on it results in an endless wait in DestroyJavaVM, even when
    // the main thread is detached beforehand - it is not clear why.
  });
}
