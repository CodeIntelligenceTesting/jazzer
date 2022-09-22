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
 * 2. starts a JVM;
 * 3. passes control to the Java part of the driver.
 */

#include <rules_jni.h>

#include <algorithm>
#include <iostream>
#include <memory>
#include <vector>

#include "absl/strings/str_split.h"
#include "jvm_tooling.h"

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
const std::string kJazzerClassName = "com/code_intelligence/jazzer/Jazzer";

void StartLibFuzzer(std::unique_ptr<jazzer::JVM> jvm,
                    std::vector<std::string> argv) {
  JNIEnv &env = jvm->GetEnv();
  jclass runner = env.FindClass(kJazzerClassName.c_str());
  if (runner == nullptr) {
    env.ExceptionDescribe();
    exit(1);
  }
  jmethodID startDriver = env.GetStaticMethodID(runner, "main", "([[B)V");
  if (startDriver == nullptr) {
    env.ExceptionDescribe();
    exit(1);
  }
  jclass byteArrayClass = env.FindClass("[B");
  if (byteArrayClass == nullptr) {
    env.ExceptionDescribe();
    exit(1);
  }
  jobjectArray args = env.NewObjectArray(argv.size(), byteArrayClass, nullptr);
  if (args == nullptr) {
    env.ExceptionDescribe();
    exit(1);
  }
  for (jsize i = 0; i < argv.size(); ++i) {
    jint len = argv[i].size();
    jbyteArray arg = env.NewByteArray(len);
    if (arg == nullptr) {
      env.ExceptionDescribe();
      exit(1);
    }
    // startDriver expects UTF-8 encoded strings that are not null-terminated.
    env.SetByteArrayRegion(arg, 0, len,
                           reinterpret_cast<const jbyte *>(argv[i].data()));
    if (env.ExceptionCheck()) {
      env.ExceptionDescribe();
      exit(1);
    }
    env.SetObjectArrayElement(args, i, arg);
    if (env.ExceptionCheck()) {
      env.ExceptionDescribe();
      exit(1);
    }
    env.DeleteLocalRef(arg);
  }
  env.CallStaticVoidMethod(runner, startDriver, args);
  // Should not return.
  if (env.ExceptionCheck()) {
    env.ExceptionDescribe();
  }
  exit(1);
}
}  // namespace

int main(int argc, char **argv) {
  rules_jni_init(argv[0]);

  for (int i = 1; i < argc; ++i) {
    const std::string &arg = argv[i];
    std::vector<std::string> split =
        absl::StrSplit(arg, absl::MaxSplits('=', 1));
    if (split.size() < 2) {
      continue;
    }
    if (split[0] == "--cp") {
      FLAGS_cp = split[1];
    } else if (split[0] == "--jvm_args") {
      FLAGS_jvm_args = split[1];
    } else if (split[0] == "--additional_jvm_args") {
      FLAGS_additional_jvm_args = split[1];
    } else if (split[0] == "--agent_path") {
      FLAGS_agent_path = split[1];
    }
  }

  if (is_asan_active) {
    std::cerr << "WARN: Jazzer is not compatible with LeakSanitizer yet. Leaks "
                 "are not reported."
              << std::endl;
  }

  StartLibFuzzer(std::unique_ptr<jazzer::JVM>(new jazzer::JVM(argv[0])),
                 std::vector<std::string>(argv, argv + argc));
}
