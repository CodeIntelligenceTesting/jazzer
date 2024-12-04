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

/*
 * Jazzer's native main function, which starts a JVM suitably configured for
 * fuzzing and passes control to the Java part of the driver.
 */

#if !defined(__ANDROID__)
#include <rules_jni.h>
#endif

#include <algorithm>
#include <memory>
#include <vector>

#include "absl/strings/str_split.h"
#include "jvm_tooling.h"

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
#if !defined(__ANDROID__)
  rules_jni_init(argv[0]);
#endif

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

  StartLibFuzzer(std::unique_ptr<jazzer::JVM>(new jazzer::JVM()),
                 std::vector<std::string>(argv + 1, argv + argc));
}
