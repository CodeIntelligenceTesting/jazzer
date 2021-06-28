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

#include "signal_handler.h"

#include <jni.h>

#include <atomic>
#include <csignal>
#include <stdexcept>

constexpr auto kSignalHandlerClass =
    "com/code_intelligence/jazzer/runtime/SignalHandler";

// Handles SIGINT raised while running Java code.
void JNICALL handleInterrupt(JNIEnv, jclass) {
  static std::atomic<bool> already_exiting{false};
  if (!already_exiting.exchange(true)) {
    // Let libFuzzer exit gracefully when the JVM received SIGINT.
    raise(SIGUSR1);
  } else {
    // Exit libFuzzer forcefully on repeated SIGINTs.
    raise(SIGTERM);
  }
}

namespace jazzer {
void SignalHandler::Setup(JNIEnv &env) {
  jclass signal_handler_class = env.FindClass(kSignalHandlerClass);
  if (env.ExceptionCheck()) {
    env.ExceptionDescribe();
    throw std::runtime_error("could not find signal handler class");
  }
  JNINativeMethod signal_handler_methods[]{
      {(char *)"handleInterrupt", (char *)"()V", (void *)&handleInterrupt},
  };
  env.RegisterNatives(signal_handler_class, signal_handler_methods, 1);
  if (env.ExceptionCheck()) {
    env.ExceptionDescribe();
    throw std::runtime_error(
        "could not register native callbacks 'handleInterrupt'");
  }
  jmethodID setup_signal_handlers_method_ =
      env.GetStaticMethodID(signal_handler_class, "setupSignalHandlers", "()V");
  if (env.ExceptionCheck()) {
    env.ExceptionDescribe();
    throw std::runtime_error("could not find setupSignalHandlers method");
  }
  env.CallStaticVoidMethod(signal_handler_class, setup_signal_handlers_method_);
  if (env.ExceptionCheck()) {
    env.ExceptionDescribe();
    throw std::runtime_error("failed to set up signal handlers");
  }
}
}  // namespace jazzer
