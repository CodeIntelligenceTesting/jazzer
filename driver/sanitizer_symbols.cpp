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

// Called in libfuzzer_driver.cpp.
extern "C" void __sanitizer_set_death_callback(void (*)()) {}

// Suppress libFuzzer warnings about missing sanitizer methods in non-sanitizer
// builds.
extern "C" int __sanitizer_acquire_crash_state() { return 1; }

namespace jazzer {
void DumpJvmStackTraces();
}

// Dump a JVM stack trace on timeouts.
extern "C" void __sanitizer_print_stack_trace() {
  jazzer::DumpJvmStackTraces();
}
