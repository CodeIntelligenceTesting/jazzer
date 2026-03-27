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

#include "counters_tracker.h"

#include <jni.h>
#include <stdint.h>

#include <iostream>
#include <vector>

#include "com_code_intelligence_jazzer_runtime_CoverageMap.h"
#include "com_code_intelligence_jazzer_runtime_ExtraCountersTracker.h"

extern "C" void __sanitizer_cov_8bit_counters_init(uint8_t *start,
                                                   uint8_t *end);
extern "C" void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg,
                                         const uintptr_t *pcs_end);
extern "C" size_t __sanitizer_cov_get_observed_pcs(uintptr_t **pc_entries);

namespace {
void AssertNoException(JNIEnv &env) {
  if (env.ExceptionCheck()) {
    env.ExceptionDescribe();
    std::cerr << "ERROR: Java exception occurred in JNI code" << std::endl;
    _Exit(1);
  }
}

// Tracks a registered PC table batch so we can update PCFlags later.
struct PCTableBatch {
  uintptr_t pc_base;
  std::size_t count;
  jazzer::PCTableEntry *entries;
};

std::vector<PCTableBatch> gCoveragePCBatches;
}  // namespace

namespace jazzer {

uint8_t *CountersTracker::coverage_counters_ = nullptr;
uint8_t *CountersTracker::extra_counters_ = nullptr;
std::mutex CountersTracker::mutex_;

void CountersTracker::RegisterCounterRange(uint8_t *start, uint8_t *end,
                                           uintptr_t pc_base,
                                           bool track_batch) {
  if (start >= end) {
    return;
  }

  std::size_t num_counters = end - start;

  // libFuzzer pairs each 8-bit counter with a PC table entry. We assign
  // globally unique synthetic PCs so the symbolizer can resolve them back
  // to Java source locations.
  PCTableEntry *pc_entries = new PCTableEntry[num_counters];
  for (std::size_t i = 0; i < num_counters; ++i) {
    pc_entries[i] = {pc_base + i, 0};
  }

  std::lock_guard<std::mutex> lock(mutex_);
  if (track_batch) {
    gCoveragePCBatches.push_back({pc_base, num_counters, pc_entries});
  }
  __sanitizer_cov_8bit_counters_init(start, end);
  __sanitizer_cov_pcs_init(
      reinterpret_cast<uintptr_t *>(pc_entries),
      reinterpret_cast<uintptr_t *>(pc_entries + num_counters));
}

void CountersTracker::Initialize(JNIEnv &env, jlong counters) {
  if (coverage_counters_ != nullptr) {
    std::cerr << "ERROR: CountersTracker::Initialize must not be called more "
                 "than once"
              << std::endl;
    _Exit(1);
  }
  coverage_counters_ =
      reinterpret_cast<uint8_t *>(static_cast<uintptr_t>(counters));
}

void CountersTracker::RegisterNewCounters(JNIEnv &env, jint old_num_counters,
                                          jint new_num_counters) {
  if (coverage_counters_ == nullptr) {
    std::cerr
        << "ERROR: CountersTracker::Initialize should have been called first"
        << std::endl;
    _Exit(1);
  }
  if (new_num_counters < old_num_counters) {
    std::cerr
        << "ERROR: new_num_counters must not be smaller than old_num_counters"
        << std::endl;
    _Exit(1);
  }
  // Coverage counters use the global edge ID as the PC value and
  // track the batch so SetCoveragePCFlags can update entries later.
  RegisterCounterRange(coverage_counters_ + old_num_counters,
                       coverage_counters_ + new_num_counters,
                       static_cast<uintptr_t>(old_num_counters),
                       /*track_batch=*/true);
}

void CountersTracker::InitializeExtra(JNIEnv &env, jlong counters) {
  if (extra_counters_ != nullptr) {
    std::cerr
        << "ERROR: CountersTracker::InitializeExtra must not be called more "
           "than once"
        << std::endl;
    _Exit(1);
  }
  extra_counters_ =
      reinterpret_cast<uint8_t *>(static_cast<uintptr_t>(counters));
}

void CountersTracker::RegisterExtraCounters(JNIEnv &env, jint start_offset,
                                            jint end_offset) {
  if (extra_counters_ == nullptr) {
    std::cerr << "ERROR: CountersTracker::InitializeExtra should have been "
                 "called first"
              << std::endl;
    _Exit(1);
  }
  if (end_offset < start_offset) {
    std::cerr << "ERROR: end_offset must not be smaller than start_offset"
              << std::endl;
    _Exit(1);
  }
  // Extra counters use a disjoint PC range so the symbolizer can tell them
  // apart from coverage counters.
  RegisterCounterRange(extra_counters_ + start_offset,
                       extra_counters_ + end_offset,
                       kExtraCountersPCBase + start_offset);
}

void CountersTracker::SetCoveragePCFlags(std::size_t edge_id, uintptr_t flags) {
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto &batch : gCoveragePCBatches) {
    if (edge_id >= batch.pc_base && edge_id < batch.pc_base + batch.count) {
      batch.entries[edge_id - batch.pc_base].PCFlags |= flags;
      return;
    }
  }
}

}  // namespace jazzer

// JNI exports for CoverageMap

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_CoverageMap_initialize(
    JNIEnv *env, jclass, jlong counters) {
  ::jazzer::CountersTracker::Initialize(*env, counters);
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_CoverageMap_registerNewCounters(
    JNIEnv *env, jclass, jint old_num_counters, jint new_num_counters) {
  ::jazzer::CountersTracker::RegisterNewCounters(*env, old_num_counters,
                                                 new_num_counters);
}

[[maybe_unused]] jintArray
Java_com_code_1intelligence_jazzer_runtime_CoverageMap_getEverCoveredIds(
    JNIEnv *env, jclass) {
  uintptr_t *covered_pcs;
  jint num_covered_pcs = __sanitizer_cov_get_observed_pcs(&covered_pcs);

  // Filter out extra-counter PCs (>= kExtraCountersPCBase) which would
  // overflow jint and corrupt Java-side coverage analysis.
  std::vector<jint> covered_edge_ids;
  covered_edge_ids.reserve(num_covered_pcs);
  for (jint i = 0; i < num_covered_pcs; ++i) {
    if (covered_pcs[i] < jazzer::kExtraCountersPCBase) {
      covered_edge_ids.push_back(static_cast<jint>(covered_pcs[i]));
    }
  }
  delete[] covered_pcs;

  jint count = static_cast<jint>(covered_edge_ids.size());
  jintArray covered_edge_ids_jni = env->NewIntArray(count);
  AssertNoException(*env);
  env->SetIntArrayRegion(covered_edge_ids_jni, 0, count,
                         covered_edge_ids.data());
  AssertNoException(*env);
  return covered_edge_ids_jni;
}

// JNI exports for ExtraCountersTracker

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_ExtraCountersTracker_initialize(
    JNIEnv *env, jclass, jlong counters) {
  ::jazzer::CountersTracker::InitializeExtra(*env, counters);
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_ExtraCountersTracker_registerCounters(
    JNIEnv *env, jclass, jint start_offset, jint end_offset) {
  ::jazzer::CountersTracker::RegisterExtraCounters(*env, start_offset,
                                                   end_offset);
}
