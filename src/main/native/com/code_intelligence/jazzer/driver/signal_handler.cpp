// Copyright 2024 Code Intelligence GmbH
//
// By downloading, you agree to the Code Intelligence Jazzer Terms and
// Conditions.
//
// The Code Intelligence Jazzer Terms and Conditions are provided in
// LICENSE-JAZZER.txt located in the root directory of the project.

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
