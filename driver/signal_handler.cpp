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

#include <atomic>
#include <csignal>
#include <stdexcept>

#include "third_party/jni/jni.h"

constexpr auto kSignalHandlerClass =
    "com/code_intelligence/jazzer/runtime/SignalHandler";

// Handles SIGINT raised while running Java code.
void JNICALL handleInterrupt() {
  static std::atomic<bool> already_exiting{false};
  if (!already_exiting.exchange(true)) {
    // Let libFuzzer exit gracefully when the JVM received SIGINT.
    raise(SIGUSR1);
  }
}

namespace jazzer {
SignalHandler::SignalHandler(JVM &jvm)
    : jvm_(jvm),
      jclass_(jvm.FindClass(kSignalHandlerClass)),
      setup_signal_handlers_method_(
          jvm.GetStaticMethodID(jclass_, "setupSignalHandlers", "()V")) {}

void SignalHandler::SetupSignalHandlers() {
  JNINativeMethod signal_handler[]{
      {(char *)"handleInterrupt", (char *)"()V", (void *)&handleInterrupt},
  };
  jvm_.GetEnv().RegisterNatives(jclass_, signal_handler, 1);
  if (jvm_.GetEnv().ExceptionCheck()) {
    jvm_.GetEnv().ExceptionDescribe();
    throw std::runtime_error(
        "could not register native callbacks 'handleInterrupt'");
  }
  jvm_.GetEnv().CallStaticVoidMethod(jclass_, setup_signal_handlers_method_);
}
}  // namespace jazzer
