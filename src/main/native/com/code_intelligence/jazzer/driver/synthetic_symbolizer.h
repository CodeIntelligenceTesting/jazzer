// Copyright 2026 Code Intelligence GmbH
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

#pragma once

#include <cstddef>
#include <cstdint>

namespace jazzer {

// Resolve a synthetic (fake) PC to a human-readable Java source location.
// Called by the __sanitizer_symbolize_pc override in sanitizer_symbols.cpp.
//
// This function is async-signal-safe: it uses a bounded spin-try-lock so it
// will never deadlock if called from a crash handler while registerLocations
// holds the write lock.
void SymbolizePC(uintptr_t pc, const char *fmt, char *out_buf,
                 size_t out_buf_size);

}  // namespace jazzer
