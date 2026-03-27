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

#include "synthetic_symbolizer.h"

#include <cstdint>
#include <cstring>
#include <string>

#include "gtest/gtest.h"

// Stubs for libFuzzer symbols pulled in transitively via counters_tracker.
extern "C" {
void __sanitizer_cov_8bit_counters_init(uint8_t *, uint8_t *) {}
void __sanitizer_cov_pcs_init(const uintptr_t *, const uintptr_t *) {}
size_t __sanitizer_cov_get_observed_pcs(uintptr_t **) { return 0; }
}

// Helper: call SymbolizePC with an unregistered PC and return the result.
static std::string Symbolize(uintptr_t pc, const char *fmt,
                             size_t buf_size = 1024) {
  std::string buf(buf_size, '\0');
  jazzer::SymbolizePC(pc, fmt, buf.data(), buf_size);
  return {buf.c_str()};
}

// The default libFuzzer format for DescribePC is "%p %F %L".
// With no registered locations, we should get clean <unknown> fallback.
TEST(SyntheticSymbolizerTest, UnregisteredPCProducesUnknownFallback) {
  auto result = Symbolize(42, "%p %F %L");
  // %p should be eaten (virtual PCs are meaningless), leaving "%F %L".
  EXPECT_NE(std::string::npos, result.find("in <unknown>"));
  EXPECT_NE(std::string::npos, result.find("<unknown>:0"));
  // No hex address should appear (the %p was consumed).
  EXPECT_EQ(std::string::npos, result.find("0x"));
}

// A small buffer should truncate without crashing.
TEST(SyntheticSymbolizerTest, SmallBufferTruncatesSafely) {
  char tiny[8] = {};
  jazzer::SymbolizePC(42, "%F %L", tiny, sizeof(tiny));
  // Must be null-terminated and not overflow.
  EXPECT_LT(strlen(tiny), sizeof(tiny));

  // Zero-size buffer is a no-op.
  char zero = 'X';
  jazzer::SymbolizePC(42, "%F", &zero, 0);
  EXPECT_EQ('X', zero);
}

// Verify individual format specifiers produce the right fallback shape.
TEST(SyntheticSymbolizerTest, FormatSpecifiers) {
  EXPECT_EQ("in <unknown>", Symbolize(42, "%F"));
  EXPECT_EQ("<unknown>:0", Symbolize(42, "%L"));
  EXPECT_EQ("<unknown>", Symbolize(42, "%s"));
  EXPECT_EQ("0", Symbolize(42, "%l"));
  EXPECT_EQ("0", Symbolize(42, "%c"));
  // Literal text passes through.
  EXPECT_EQ("hello", Symbolize(42, "hello"));
}
