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

/*
 * Jazzer's native main function, which:
 * 1. defines default settings for ASan and UBSan;
 * 2. preprocesses the command-line arguments passed to libFuzzer;
 * 3. starts a JVM;
 * 4. passes control to the Java-part of the driver.
 */

#include <rules_jni.h>

#include <algorithm>
#include <iostream>
#include <memory>
#include <vector>

#include "absl/strings/match.h"
#include "gflags/gflags.h"
#include "jvm_tooling.h"

// Defined by glog
DECLARE_bool(log_prefix);

namespace {
bool is_asan_active = false;
}

extern "C" {
[[maybe_unused]] const char *__asan_default_options() {
  is_asan_active = true;
  // LeakSanitizer is not yet supported as it reports too many false positives
  // due to how the JVM GC works.
  // We use a distinguished exit code to recognize ASan crashes in tests.
  // Also specify abort_on_error=0 explicitly since ASan aborts rather than
  // exits on macOS by default, which would cause our exit code to be ignored.
  return "abort_on_error=0,detect_leaks=0,exitcode=76";
}

[[maybe_unused]] const char *__ubsan_default_options() {
  // We use a distinguished exit code to recognize UBSan crashes in tests.
  // Also specify abort_on_error=0 explicitly since UBSan aborts rather than
  // exits on macOS by default, which would cause our exit code to be ignored.
  return "abort_on_error=0,exitcode=76";
}
}

namespace {
const std::string kUsageMessage =
    R"(Test java fuzz targets using libFuzzer. Usage:
  jazzer --cp=<java_class_path> --target_class=<fuzz_target_class> <libfuzzer_arguments...>)";
const std::string kDriverClassName =
    "com/code_intelligence/jazzer/driver/Driver";

int StartLibFuzzer(std::unique_ptr<jazzer::JVM> jvm,
                   std::vector<std::string> argv) {
  JNIEnv &env = jvm->GetEnv();
  jclass runner = env.FindClass(kDriverClassName.c_str());
  if (runner == nullptr) {
    env.ExceptionDescribe();
    return 1;
  }
  jmethodID startDriver = env.GetStaticMethodID(runner, "start", "([[B)I");
  if (startDriver == nullptr) {
    env.ExceptionDescribe();
    return 1;
  }
  jclass byteArrayClass = env.FindClass("[B");
  if (byteArrayClass == nullptr) {
    env.ExceptionDescribe();
    return 1;
  }
  jobjectArray args = env.NewObjectArray(argv.size(), byteArrayClass, nullptr);
  if (args == nullptr) {
    env.ExceptionDescribe();
    return 1;
  }
  for (jsize i = 0; i < argv.size(); ++i) {
    jint len = argv[i].size();
    jbyteArray arg = env.NewByteArray(len);
    if (arg == nullptr) {
      env.ExceptionDescribe();
      return 1;
    }
    // startDriver expects UTF-8 encoded strings that are not null-terminated.
    env.SetByteArrayRegion(arg, 0, len,
                           reinterpret_cast<const jbyte *>(argv[i].data()));
    if (env.ExceptionCheck()) {
      env.ExceptionDescribe();
      return 1;
    }
    env.SetObjectArrayElement(args, i, arg);
    if (env.ExceptionCheck()) {
      env.ExceptionDescribe();
      return 1;
    }
    env.DeleteLocalRef(arg);
  }
  int res = env.CallStaticIntMethod(runner, startDriver, args);
  if (env.ExceptionCheck()) {
    env.ExceptionDescribe();
    return 1;
  }
  env.DeleteLocalRef(args);
  return res;
}
}  // namespace

int main(int argc, char **argv) {
  gflags::SetUsageMessage(kUsageMessage);
  rules_jni_init(argv[0]);

  const auto argv_end = argv + argc;

  {
    // All libFuzzer flags start with a single dash, our arguments all start
    // with a double dash. We can thus filter out the arguments meant for gflags
    // by taking only those with a leading double dash.
    std::vector<char *> our_args = {*argv};
    std::copy_if(argv, argv_end, std::back_inserter(our_args),
                 [](const std::string &arg) {
                   return absl::StartsWith(std::string(arg), "--");
                 });
    int our_argc = our_args.size();
    char **our_argv = our_args.data();
    // Let gflags consume its flags, but keep them in the argument list in case
    // libFuzzer forwards the command line (e.g. with -jobs or -minimize_crash).
    gflags::ParseCommandLineFlags(&our_argc, &our_argv, false);
  }

  if (is_asan_active) {
    std::cerr << "WARN: Jazzer is not compatible with LeakSanitizer yet. Leaks "
                 "are not reported."
              << std::endl;
  }

  return StartLibFuzzer(std::unique_ptr<jazzer::JVM>(new jazzer::JVM(argv[0])),
                        std::vector<std::string>(argv, argv_end));
}
