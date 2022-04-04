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

#include <iostream>

#include "libfuzzer_driver.h"

namespace {
bool is_asan_active = false;
}

extern "C" {
const char *__asan_default_options() {
  is_asan_active = true;
  // LeakSanitizer is not yet supported as it reports too many false positives
  // due to how the JVM GC works.
  // We use a distinguished exit code to recognize ASan crashes in tests.
  // Also specify abort_on_error=0 explicitly since ASan aborts rather than
  // exits on macOS by default, which would cause our exit code to be ignored.
  return "abort_on_error=0,detect_leaks=0,exitcode=76";
}

const char *__ubsan_default_options() {
  // We use a distinguished exit code to recognize UBSan crashes in tests.
  // Also specify abort_on_error=0 explicitly since UBSan aborts rather than
  // exits on macOS by default, which would cause our exit code to be ignored.
  return "abort_on_error=0,exitcode=76";
}
}

namespace {
using Driver = jazzer::LibfuzzerDriver;

std::unique_ptr<Driver> gLibfuzzerDriver;
}  // namespace

extern "C" void driver_cleanup() {
  // Free the libfuzzer driver which triggers a clean JVM shutdown.
  gLibfuzzerDriver.reset(nullptr);
}

// This symbol is defined by sanitizers if linked into Jazzer or in
// sanitizer_symbols.cpp if no sanitizer is used.
extern "C" void __sanitizer_set_death_callback(void (*)());

// We apply a patch to libFuzzer to make it call this function instead of
// __sanitizer_set_death_callback to pass us the death callback.
extern "C" [[maybe_unused]] void __jazzer_set_death_callback(
    void (*callback)()) {
  jazzer::AbstractLibfuzzerDriver::libfuzzer_print_crashing_input_ = callback;
  __sanitizer_set_death_callback([]() {
    jazzer::DumpJvmStackTraces();
    jazzer::AbstractLibfuzzerDriver::libfuzzer_print_crashing_input_();
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

// Entry point called by libfuzzer before any LLVMFuzzerTestOneInput(...)
// invocations.
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  if (is_asan_active) {
    std::cerr << "WARN: Jazzer is not compatible with LeakSanitizer yet. Leaks "
                 "are not reported."
              << std::endl;
  }
  gLibfuzzerDriver = std::make_unique<Driver>(argc, argv);
  std::atexit(&driver_cleanup);
  return 0;
}

#ifndef _WIN32
__attribute__((weak))
#endif
extern "C" int
__llvm_profile_write_file(void) {
  return 0;
}

// Called by the fuzzer for every fuzzing input.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, const size_t size) {
  auto result = gLibfuzzerDriver->TestOneInput(data, size);
  if (result != jazzer::RunResult::kOk) {
    // Fuzzer triggered an exception or assertion in Java code. Skip the
    // uninformative libFuzzer stack trace.
    std::cerr << "== libFuzzer crashing input ==\n";
    Driver::libfuzzer_print_crashing_input_();
    // DumpReproducer needs to be called after libFuzzer printed its final
    // stats as otherwise it would report incorrect coverage.
    gLibfuzzerDriver->DumpReproducer(data, size);
    if (result == jazzer::RunResult::kDumpAndContinue) {
      // Continue fuzzing after printing the crashing input.
      return 0;
    }
    // Exit directly without invoking libFuzzer's atexit hook.
    driver_cleanup();
    // When running with LLVM coverage instrumentation, write out the profile as
    // the exit hook that write it won't run.
    __llvm_profile_write_file();
    _Exit(Driver::kErrorExitCode);
  }
  return 0;
}
