// Copyright 2024 Code Intelligence GmbH
//
// By downloading, you agree to the Code Intelligence Jazzer Terms and
// Conditions.
//
// The Code Intelligence Jazzer Terms and Conditions are provided in
// LICENSE-JAZZER.txt located in the root directory of the project.

// Suppress libFuzzer warnings about missing sanitizer methods in non-sanitizer
// builds.
extern "C" [[maybe_unused]] int __sanitizer_acquire_crash_state() { return 1; }

namespace jazzer {
void DumpJvmStackTraces();
}

// Dump a JVM stack trace on timeouts.
extern "C" [[maybe_unused]] void __sanitizer_print_stack_trace() {
  jazzer::DumpJvmStackTraces();
}
