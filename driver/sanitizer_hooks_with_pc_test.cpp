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

#include "sanitizer_hooks_with_pc.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iostream>

#include "gtest/gtest.h"

static std::vector<uint16_t> gCoverageMap(512);

inline void __attribute__((always_inline)) RecordCoverage() {
  auto return_address =
      reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  auto idx = return_address & (gCoverageMap.size() - 1);
  gCoverageMap[idx]++;
}

extern "C" {
void __sanitizer_cov_trace_cmp4(uint32_t arg1, uint32_t arg2) {
  RecordCoverage();
}

void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2) {
  RecordCoverage();
}

void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) {
  RecordCoverage();
}

void __sanitizer_cov_trace_div4(uint32_t val) { RecordCoverage(); }

void __sanitizer_cov_trace_div8(uint64_t val) { RecordCoverage(); }

void __sanitizer_cov_trace_gep(uintptr_t idx) { RecordCoverage(); }

void __sanitizer_cov_trace_pc_indir(uintptr_t callee) { RecordCoverage(); }
}

void ClearCoverage() { std::fill(gCoverageMap.begin(), gCoverageMap.end(), 0); }

bool HasOptimalPcCoverage() {
#ifdef __aarch64__
  // All arm64 instructions are four bytes long and aligned to four bytes, so
  // the lower two bits of each PC are fixed to 00.
  return std::count(gCoverageMap.cbegin(), gCoverageMap.cend(), 0) <=
         3 * gCoverageMap.size() / 4;
#else
  return std::count(gCoverageMap.cbegin(), gCoverageMap.cend(), 0) == 0;
#endif
}

bool HasSingleCoveredPc() {
  return std::count(gCoverageMap.cbegin(), gCoverageMap.cend(), 0) ==
         gCoverageMap.size() - 1;
}

std::string PrettyPrintCoverage() {
  std::ostringstream out;
  std::size_t break_after = 16;
  out << "Coverage:" << std::endl;
  for (uintptr_t i = 0; i < gCoverageMap.size(); i++) {
    out << (gCoverageMap[i] ? "X" : "_");
    if (i % break_after == break_after - 1) out << std::endl;
  }
  return out.str();
}

class TestFakePcTrampoline : public ::testing::Test {
 protected:
  TestFakePcTrampoline() {
    ClearCoverage();
    CalibrateTrampoline();
  }
};

TEST_F(TestFakePcTrampoline, TraceCmp4Direct) {
  for (uint32_t i = 0; i < gCoverageMap.size(); ++i) {
    __sanitizer_cov_trace_cmp4(i, i);
  }
  EXPECT_TRUE(HasSingleCoveredPc()) << PrettyPrintCoverage();
}

TEST_F(TestFakePcTrampoline, TraceCmp8Direct) {
  for (uint32_t i = 0; i < gCoverageMap.size(); ++i) {
    __sanitizer_cov_trace_cmp8(i, i);
  }
  EXPECT_TRUE(HasSingleCoveredPc()) << PrettyPrintCoverage();
}

TEST_F(TestFakePcTrampoline, TraceSwitchDirect) {
  for (uint32_t i = 0; i < gCoverageMap.size(); ++i) {
    __sanitizer_cov_trace_switch(i, nullptr);
  }
  EXPECT_TRUE(HasSingleCoveredPc()) << PrettyPrintCoverage();
}

TEST_F(TestFakePcTrampoline, TraceDiv4Direct) {
  for (uint32_t i = 0; i < gCoverageMap.size(); ++i) {
    __sanitizer_cov_trace_div4(i);
  }
  EXPECT_TRUE(HasSingleCoveredPc()) << PrettyPrintCoverage();
}

TEST_F(TestFakePcTrampoline, TraceDiv8Direct) {
  for (uint32_t i = 0; i < gCoverageMap.size(); ++i) {
    __sanitizer_cov_trace_div8(i);
  }
  EXPECT_TRUE(HasSingleCoveredPc()) << PrettyPrintCoverage();
}

TEST_F(TestFakePcTrampoline, TraceGepDirect) {
  for (uint32_t i = 0; i < gCoverageMap.size(); ++i) {
    __sanitizer_cov_trace_gep(i);
  }
  EXPECT_TRUE(HasSingleCoveredPc()) << PrettyPrintCoverage();
}

TEST_F(TestFakePcTrampoline, TracePcIndirDirect) {
  for (uint32_t i = 0; i < gCoverageMap.size(); ++i) {
    __sanitizer_cov_trace_pc_indir(i);
  }
  EXPECT_TRUE(HasSingleCoveredPc()) << PrettyPrintCoverage();
}

TEST_F(TestFakePcTrampoline, TraceCmp4Trampoline) {
  for (uint32_t i = 0; i < gCoverageMap.size(); ++i) {
    __sanitizer_cov_trace_cmp4_with_pc(reinterpret_cast<void *>(i), i, i);
  }
  EXPECT_TRUE(HasOptimalPcCoverage()) << PrettyPrintCoverage();
}

TEST_F(TestFakePcTrampoline, TraceCmp8Trampoline) {
  for (uint32_t i = 0; i < gCoverageMap.size(); ++i) {
    __sanitizer_cov_trace_cmp8_with_pc(reinterpret_cast<void *>(i), i, i);
  }
  EXPECT_TRUE(HasOptimalPcCoverage()) << PrettyPrintCoverage();
}

TEST_F(TestFakePcTrampoline, TraceSwitchTrampoline) {
  for (uint32_t i = 0; i < gCoverageMap.size(); ++i) {
    __sanitizer_cov_trace_switch_with_pc(reinterpret_cast<void *>(i), i,
                                         nullptr);
  }
  EXPECT_TRUE(HasOptimalPcCoverage()) << PrettyPrintCoverage();
}

TEST_F(TestFakePcTrampoline, TraceDiv4Trampoline) {
  for (uint32_t i = 0; i < gCoverageMap.size(); ++i) {
    __sanitizer_cov_trace_div4_with_pc(reinterpret_cast<void *>(i), i);
  }
  EXPECT_TRUE(HasOptimalPcCoverage()) << PrettyPrintCoverage();
}

TEST_F(TestFakePcTrampoline, TraceDiv8Trampoline) {
  for (uint32_t i = 0; i < gCoverageMap.size(); ++i) {
    __sanitizer_cov_trace_div8_with_pc(reinterpret_cast<void *>(i), i);
  }
  EXPECT_TRUE(HasOptimalPcCoverage()) << PrettyPrintCoverage();
}

TEST_F(TestFakePcTrampoline, TraceGepTrampoline) {
  for (uint32_t i = 0; i < gCoverageMap.size(); ++i) {
    __sanitizer_cov_trace_gep_with_pc(reinterpret_cast<void *>(i), i);
  }
  EXPECT_TRUE(HasOptimalPcCoverage()) << PrettyPrintCoverage();
}

TEST_F(TestFakePcTrampoline, TracePcIndirTrampoline) {
  for (uint32_t i = 0; i < gCoverageMap.size(); ++i) {
    __sanitizer_cov_trace_pc_indir_with_pc(reinterpret_cast<void *>(i), i);
  }
  EXPECT_TRUE(HasOptimalPcCoverage()) << PrettyPrintCoverage();
}
