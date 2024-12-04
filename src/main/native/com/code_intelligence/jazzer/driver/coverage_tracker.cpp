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

#include "coverage_tracker.h"

#include <jni.h>
#include <stdint.h>

#include <iostream>
#include <vector>

#include "com_code_intelligence_jazzer_runtime_CoverageMap.h"

extern "C" void __sanitizer_cov_8bit_counters_init(uint8_t *start,
                                                   uint8_t *end);
extern "C" void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg,
                                         const uintptr_t *pcs_end);
extern "C" size_t __sanitizer_cov_get_observed_pcs(uintptr_t **pc_entries);

namespace {
void AssertNoException(JNIEnv &env) {
  if (env.ExceptionCheck()) {
    env.ExceptionDescribe();
    std::cerr << "ERROR: Java exception occurred in CoverageTracker JNI code"
              << std::endl;
    _Exit(1);
  }
}
}  // namespace

namespace jazzer {

uint8_t *CoverageTracker::counters_ = nullptr;
PCTableEntry *CoverageTracker::pc_entries_ = nullptr;

void CoverageTracker::Initialize(JNIEnv &env, jlong counters) {
  if (counters_ != nullptr) {
    std::cerr << "ERROR: CoverageTracker::Initialize must not be called more "
                 "than once"
              << std::endl;
    _Exit(1);
  }
  counters_ = reinterpret_cast<uint8_t *>(static_cast<uintptr_t>(counters));
}

void CoverageTracker::RegisterNewCounters(JNIEnv &env, jint old_num_counters,
                                          jint new_num_counters) {
  if (counters_ == nullptr) {
    std::cerr
        << "ERROR: CoverageTracker::Initialize should have been called first"
        << std::endl;
    _Exit(1);
  }
  if (new_num_counters < old_num_counters) {
    std::cerr
        << "ERROR: new_num_counters must not be smaller than old_num_counters"
        << std::endl;
    _Exit(1);
  }
  if (new_num_counters == old_num_counters) {
    return;
  }
  std::size_t diff_num_counters = new_num_counters - old_num_counters;
  // libFuzzer requires an array containing the instruction addresses associated
  // with the coverage counters registered above. This is required to report how
  // many edges have been covered. However, libFuzzer only checks these
  // addresses when the corresponding flag is set to 1. Therefore, it is safe to
  // set the all PC entries to any value as long as the corresponding flag is
  // set to zero. We set the value of each PC to the index of the corresponding
  // edge ID. This facilitates finding the edge ID of each covered PC reported
  // by libFuzzer.
  pc_entries_ = new PCTableEntry[diff_num_counters];
  for (std::size_t i = 0; i < diff_num_counters; ++i) {
    pc_entries_[i] = {i, 0};
  }
  __sanitizer_cov_8bit_counters_init(counters_ + old_num_counters,
                                     counters_ + new_num_counters);
  __sanitizer_cov_pcs_init((uintptr_t *)(pc_entries_),
                           (uintptr_t *)(pc_entries_ + diff_num_counters));
}
}  // namespace jazzer

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_CoverageMap_initialize(
    JNIEnv *env, jclass, jlong counters) {
  ::jazzer::CoverageTracker::Initialize(*env, counters);
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_CoverageMap_registerNewCounters(
    JNIEnv *env, jclass, jint old_num_counters, jint new_num_counters) {
  ::jazzer::CoverageTracker::RegisterNewCounters(*env, old_num_counters,
                                                 new_num_counters);
}

[[maybe_unused]] jintArray
Java_com_code_1intelligence_jazzer_runtime_CoverageMap_getEverCoveredIds(
    JNIEnv *env, jclass) {
  uintptr_t *covered_pcs;
  jint num_covered_pcs = __sanitizer_cov_get_observed_pcs(&covered_pcs);
  std::vector<jint> covered_edge_ids(covered_pcs,
                                     covered_pcs + num_covered_pcs);
  delete[] covered_pcs;

  jintArray covered_edge_ids_jni = env->NewIntArray(num_covered_pcs);
  AssertNoException(*env);
  env->SetIntArrayRegion(covered_edge_ids_jni, 0, num_covered_pcs,
                         covered_edge_ids.data());
  AssertNoException(*env);
  return covered_edge_ids_jni;
}
