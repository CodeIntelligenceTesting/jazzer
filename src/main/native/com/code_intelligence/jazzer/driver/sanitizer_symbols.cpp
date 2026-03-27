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

#include "synthetic_symbolizer.h"

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

// Override libFuzzer's weak __sanitizer_symbolize_pc so that -print_pcs=1,
// -print_funcs=1, and -print_coverage=1 show Java source locations.
extern "C" [[maybe_unused]] void __sanitizer_symbolize_pc(void *pc,
                                                          const char *fmt,
                                                          char *out_buf,
                                                          size_t out_buf_size) {
  jazzer::SymbolizePC(reinterpret_cast<uintptr_t>(pc), fmt, out_buf,
                      out_buf_size);
}
