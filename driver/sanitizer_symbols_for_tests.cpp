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

#include <cstddef>
#include <cstdint>

// Symbols exported by libFuzzer that are required by libfuzzer_callbacks and
// CoverageTracker.
extern "C" {
void __sanitizer_cov_8bit_counters_init(uint8_t *start, uint8_t *end) {}
void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg,
                              const uintptr_t *pcs_end) {}
size_t __sanitizer_cov_get_observed_pcs(uintptr_t **pc_entries) {
  *pc_entries = new uintptr_t[0];
  return 0;
}
void __sanitizer_weak_hook_compare_bytes(void *caller_pc, const void *s1,
                                         const void *s2, std::size_t n1,
                                         std::size_t n2, int result) {}
void __sanitizer_weak_hook_memmem(void *called_pc, const void *s1, size_t len1,
                                  const void *s2, size_t len2, void *result) {}
void __sanitizer_cov_trace_cmp4(uint32_t arg1, uint32_t arg2) {}
void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2) {}
void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) {}
void __sanitizer_cov_trace_div4(uint32_t val) {}
void __sanitizer_cov_trace_div8(uint64_t val) {}
void __sanitizer_cov_trace_gep(uintptr_t idx) {}
void __sanitizer_cov_trace_pc_indir(uintptr_t callee) {}
void __sanitizer_set_death_callback(void (*callback)()) {}
}
