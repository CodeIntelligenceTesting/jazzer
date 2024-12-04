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

#pragma once

#include <cstdint>

// This file declares variants of the libFuzzer compare, division, switch and
// gep hooks that accept an additional caller_pc argument that can be used to
// pass a custom value that is recorded as the caller's instruction pointer
// ("program counter"). This allows synthetic program counters obtained from
// Java coverage information to be used with libFuzzer's value profile, with
// which it records detailed information about the result of compares and
// associates it with particular coverage locations.
//
// Note: Only the lower 9 bits of the caller_pc argument are used by libFuzzer.
#ifdef __cplusplus
extern "C" {
#endif
void __sanitizer_cov_trace_cmp4_with_pc(void *caller_pc, uint32_t arg1,
                                        uint32_t arg2);
void __sanitizer_cov_trace_cmp8_with_pc(void *caller_pc, uint64_t arg1,
                                        uint64_t arg2);

void __sanitizer_cov_trace_switch_with_pc(void *caller_pc, uint64_t val,
                                          uint64_t *cases);

void __sanitizer_cov_trace_div4_with_pc(void *caller_pc, uint32_t val);
void __sanitizer_cov_trace_div8_with_pc(void *caller_pc, uint64_t val);

void __sanitizer_cov_trace_gep_with_pc(void *caller_pc, uintptr_t idx);

void __sanitizer_cov_trace_pc_indir_with_pc(void *caller_pc, uintptr_t callee);
#ifdef __cplusplus
}
#endif
