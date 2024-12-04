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

#include <jni.h>

#include <atomic>
#include <csignal>

#include "com_code_intelligence_jazzer_driver_SignalHandler.h"

#ifdef _WIN32
// Windows does not have SIGUSR1, which triggers a graceful exit of libFuzzer.
// Instead, trigger a hard exit.
#define SIGUSR1 SIGTERM
#endif

// Handles SIGINT raised while running Java code.
[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_driver_SignalHandler_handleInterrupt(
    JNIEnv *, jclass) {
  static std::atomic<bool> already_exiting{false};
  if (!already_exiting.exchange(true)) {
    // Let libFuzzer exit gracefully when the JVM received SIGINT.
    raise(SIGUSR1);
  } else {
    // Exit libFuzzer forcefully on repeated SIGINTs.
    raise(SIGTERM);
  }
}
