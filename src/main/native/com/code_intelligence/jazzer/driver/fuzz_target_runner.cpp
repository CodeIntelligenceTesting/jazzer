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

/**
 * A native wrapper around the FuzzTargetRunner Java class that executes it as a
 * libFuzzer fuzz target.
 */

#include "fuzz_target_runner.h"

#ifndef _WIN32
#include <dlfcn.h>
#endif
#include <jni.h>
#include <stdint.h>

#include <iostream>
#include <limits>
#include <string>
#include <vector>

#include "com_code_intelligence_jazzer_runtime_FuzzTargetRunnerNatives.h"

extern "C" int LLVMFuzzerRunDriver(int *argc, char ***argv,
                                   int (*UserCb)(const uint8_t *Data,
                                                 size_t Size));
extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

namespace {
jclass gRunner;
jmethodID gRunOneId;
jmethodID gMutateOneId;
jmethodID gCrossOverId;
JavaVM *gJavaVm;
JNIEnv *gEnv;
jboolean gUseMutatorFramework;

// A libFuzzer-registered callback that outputs the crashing input, but does
// not include a stack trace.
void (*gLibfuzzerPrintCrashingInput)() = nullptr;

int testOneInput(const uint8_t *data, const std::size_t size) {
  JNIEnv &env = *gEnv;
  jint jsize =
      std::min(size, static_cast<size_t>(std::numeric_limits<jint>::max()));
  int res = env.CallStaticIntMethod(gRunner, gRunOneId, data, jsize);
  if (env.ExceptionCheck()) {
    env.ExceptionDescribe();
    _Exit(1);
  }
  return res;
}
}  // namespace

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
  if (gUseMutatorFramework) {
    JNIEnv &env = *gEnv;
    jint jsize =
        std::min(Size, static_cast<size_t>(std::numeric_limits<jint>::max()));
    jint jmaxSize = std::min(
        MaxSize, static_cast<size_t>(std::numeric_limits<jint>::max()));
    jint jseed = static_cast<jint>(Seed);
    jint newSize = env.CallStaticLongMethod(gRunner, gMutateOneId, Data, jsize,
                                            jmaxSize, jseed);
    if (env.ExceptionCheck()) {
      env.ExceptionDescribe();
      _Exit(1);
    }
    return static_cast<uint32_t>(newSize);
  } else {
    return LLVMFuzzerMutate(Data, Size, MaxSize);
  }
}

extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t *Data1, size_t Size1,
                                            const uint8_t *Data2, size_t Size2,
                                            uint8_t *Out, size_t MaxOutSize,
                                            unsigned int Seed) {
  if (gUseMutatorFramework) {
    JNIEnv &env = *gEnv;
    jint jsize1 =
        std::min(Size1, static_cast<size_t>(std::numeric_limits<jint>::max()));
    jint jsize2 =
        std::min(Size2, static_cast<size_t>(std::numeric_limits<jint>::max()));
    jint jMaxOutSize = std::min(
        MaxOutSize, static_cast<size_t>(std::numeric_limits<jint>::max()));
    jint jseed = static_cast<jint>(Seed);

    jint newSize =
        env.CallStaticLongMethod(gRunner, gCrossOverId, Data1, jsize1, Data2,
                                 jsize2, Out, jMaxOutSize, jseed);
    if (env.ExceptionCheck()) {
      env.ExceptionDescribe();
      _Exit(1);
    }
    return static_cast<uint32_t>(newSize);
  } else {
    // No custom cross over supported.
    return 0;
  }
}

namespace jazzer {
void DumpJvmStackTraces() {
  JNIEnv *env = nullptr;
  if (gJavaVm->AttachCurrentThread(reinterpret_cast<void **>(&env), nullptr) !=
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

[[maybe_unused]] jint
Java_com_code_1intelligence_jazzer_runtime_FuzzTargetRunnerNatives_startLibFuzzer(
    JNIEnv *env, jclass, jobjectArray args, jclass runner,
    jboolean useMutatorFramework) {
  gUseMutatorFramework = useMutatorFramework;
  gEnv = env;
  env->GetJavaVM(&gJavaVm);
  gRunner = reinterpret_cast<jclass>(env->NewGlobalRef(runner));
  gRunOneId = env->GetStaticMethodID(runner, "runOne", "(JI)I");
  gMutateOneId = env->GetStaticMethodID(runner, "mutateOne", "(JIII)I");
  gCrossOverId = env->GetStaticMethodID(runner, "crossOver", "(JIJIJII)I");
  if (gRunOneId == nullptr) {
    env->ExceptionDescribe();
    _Exit(1);
  }

  int argc = env->GetArrayLength(args);
  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    _Exit(1);
  }
  std::vector<std::string> argv_strings;
  std::vector<const char *> argv_c;
  for (jsize i = 0; i < argc; i++) {
    auto arg_jni =
        reinterpret_cast<jbyteArray>(env->GetObjectArrayElement(args, i));
    if (arg_jni == nullptr) {
      env->ExceptionDescribe();
      _Exit(1);
    }
    jbyte *arg_c = env->GetByteArrayElements(arg_jni, nullptr);
    if (arg_c == nullptr) {
      env->ExceptionDescribe();
      _Exit(1);
    }
    std::size_t arg_size = env->GetArrayLength(arg_jni);
    if (env->ExceptionCheck()) {
      env->ExceptionDescribe();
      _Exit(1);
    }
    argv_strings.emplace_back(reinterpret_cast<const char *>(arg_c), arg_size);
    env->ReleaseByteArrayElements(arg_jni, arg_c, JNI_ABORT);
    if (env->ExceptionCheck()) {
      env->ExceptionDescribe();
      _Exit(1);
    }
  }
  for (jsize i = 0; i < argc; i++) {
    argv_c.emplace_back(argv_strings[i].c_str());
  }
  // Null-terminate argv.
  argv_c.emplace_back(nullptr);

  const char **argv = argv_c.data();
  return LLVMFuzzerRunDriver(&argc, const_cast<char ***>(&argv), testOneInput);
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_FuzzTargetRunnerNatives_printAndDumpCrashingInput(
    JNIEnv *, jclass) {
  if (gLibfuzzerPrintCrashingInput == nullptr) {
    std::cerr << "<not available>" << std::endl;
  } else {
    gLibfuzzerPrintCrashingInput();
  }
}

namespace fuzzer {
// Defined in:
// https://github.com/llvm/llvm-project/blob/27cc31b64c0491725aa88a6822f0f2a2c18914d7/compiler-rt/lib/fuzzer/FuzzerLoop.cpp#L43
// Used here:
// https://github.com/llvm/llvm-project/blob/27cc31b64c0491725aa88a6822f0f2a2c18914d7/compiler-rt/lib/fuzzer/FuzzerLoop.cpp#L244
extern bool RunningUserCallback;
}  // namespace fuzzer

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_FuzzTargetRunnerNatives_temporarilyDisableLibfuzzerExitHook(
    JNIEnv *, jclass) {
  ::fuzzer::RunningUserCallback = false;
}

// We apply a patch to libFuzzer to make it call this function instead of
// __sanitizer_set_death_callback to pass us the death callback.
extern "C" [[maybe_unused]] void __jazzer_set_death_callback(
    void (*callback)()) {
  gLibfuzzerPrintCrashingInput = callback;
#ifndef _WIN32
  void *sanitizer_set_death_callback =
      dlsym(RTLD_DEFAULT, "__sanitizer_set_death_callback");
  if (sanitizer_set_death_callback != nullptr) {
    (reinterpret_cast<void (*)(void (*)())>(sanitizer_set_death_callback))(
        []() {
          ::jazzer::DumpJvmStackTraces();
          gLibfuzzerPrintCrashingInput();
          // Ideally, we would be able to perform a graceful shutdown of the
          // JVM. However, doing this directly results in a nested bug report by
          // ASan or UBSan, likely because something about the stack/thread
          // context in which they generate reports is incompatible with the JVM
          // shutdown process. use_sigaltstack=0 does not help though, so this
          // might be on us.
        });
  }
#endif
}
