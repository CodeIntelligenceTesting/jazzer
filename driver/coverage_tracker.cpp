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

#include "coverage_tracker.h"

#include <jni.h>

#include <algorithm>
#include <memory>
#include <stdexcept>
#include <vector>

#include "com_code_intelligence_jazzer_runtime_CoverageMap.h"

extern "C" void __sanitizer_cov_8bit_counters_init(uint8_t *start,
                                                   uint8_t *end);
extern "C" void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg,
                                         const uintptr_t *pcs_end);
extern "C" size_t __sanitizer_cov_get_observed_pcs(uintptr_t **pc_entries);

constexpr auto kCoverageRecorderClass =
    "com/code_intelligence/jazzer/instrumentor/CoverageRecorder";

namespace {
void AssertNoException(JNIEnv &env) {
  if (env.ExceptionCheck()) {
    env.ExceptionDescribe();
    throw std::runtime_error(
        "Java exception occurred in CoverageTracker JNI code");
  }
}
}  // namespace

namespace jazzer {

uint8_t *CoverageTracker::counters_ = nullptr;
PCTableEntry *CoverageTracker::pc_entries_ = nullptr;

void CoverageTracker::Initialize(JNIEnv &env, jlong counters) {
  if (counters_ != nullptr) {
    throw std::runtime_error(
        "CoverageTracker::Initialize must not be called more than once");
  }
  counters_ = reinterpret_cast<uint8_t *>(static_cast<uintptr_t>(counters));
}

void CoverageTracker::RegisterNewCounters(JNIEnv &env, jint old_num_counters,
                                          jint new_num_counters) {
  if (counters_ == nullptr) {
    throw std::runtime_error(
        "CoverageTracker::Initialize should have been called first");
  }
  if (new_num_counters < old_num_counters) {
    throw std::runtime_error(
        "new_num_counters must not be smaller than old_num_counters");
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

uint8_t *CoverageTracker::GetCoverageCounters() { return counters_; }

void CoverageTracker::RecordInitialCoverage(JNIEnv &env) {
  jclass coverage_recorder = env.FindClass(kCoverageRecorderClass);
  AssertNoException(env);
  jmethodID coverage_recorder_update_covered_ids_with_coverage_map =
      env.GetStaticMethodID(coverage_recorder,
                            "updateCoveredIdsWithCoverageMap", "()V");
  AssertNoException(env);
  env.CallStaticVoidMethod(
      coverage_recorder,
      coverage_recorder_update_covered_ids_with_coverage_map);
  AssertNoException(env);
}

void CoverageTracker::ReplayInitialCoverage(JNIEnv &env) {
  jclass coverage_recorder = env.FindClass(kCoverageRecorderClass);
  AssertNoException(env);
  jmethodID coverage_recorder_update_covered_ids_with_coverage_map =
      env.GetStaticMethodID(coverage_recorder, "replayCoveredIds", "()V");
  AssertNoException(env);
  env.CallStaticVoidMethod(
      coverage_recorder,
      coverage_recorder_update_covered_ids_with_coverage_map);
  AssertNoException(env);
}

void CoverageTracker::ReportCoverage(JNIEnv &env, std::string report_file) {
  uintptr_t *covered_pcs;
  size_t num_covered_pcs = __sanitizer_cov_get_observed_pcs(&covered_pcs);
  std::vector<jint> covered_edge_ids(covered_pcs,
                                     covered_pcs + num_covered_pcs);
  delete[] covered_pcs;

  jclass coverage_recorder = env.FindClass(kCoverageRecorderClass);
  AssertNoException(env);
  jmethodID coverage_recorder_dump_coverage_report = env.GetStaticMethodID(
      coverage_recorder, "dumpCoverageReport", "([ILjava/lang/String;)V");
  AssertNoException(env);
  jintArray covered_edge_ids_jni = env.NewIntArray(num_covered_pcs);
  AssertNoException(env);
  env.SetIntArrayRegion(covered_edge_ids_jni, 0, num_covered_pcs,
                        covered_edge_ids.data());
  AssertNoException(env);
  jstring report_file_str = env.NewStringUTF(report_file.c_str());
  env.CallStaticVoidMethod(coverage_recorder,
                           coverage_recorder_dump_coverage_report,
                           covered_edge_ids_jni, report_file_str);
  AssertNoException(env);
}

void CoverageTracker::DumpCoverage(JNIEnv &env, std::string dump_file) {
  uintptr_t *covered_pcs;
  size_t num_covered_pcs = __sanitizer_cov_get_observed_pcs(&covered_pcs);
  std::vector<jint> covered_edge_ids(covered_pcs,
                                     covered_pcs + num_covered_pcs);
  delete[] covered_pcs;

  jclass coverage_recorder = env.FindClass(kCoverageRecorderClass);
  AssertNoException(env);
  jmethodID coverage_recorder_dump_jacoco_coverage = env.GetStaticMethodID(
      coverage_recorder, "dumpJacocoCoverage", "([ILjava/lang/String;)V");
  AssertNoException(env);
  jintArray covered_edge_ids_jni = env.NewIntArray(num_covered_pcs);
  AssertNoException(env);
  env.SetIntArrayRegion(covered_edge_ids_jni, 0, num_covered_pcs,
                        covered_edge_ids.data());
  AssertNoException(env);
  jstring dump_file_str = env.NewStringUTF(dump_file.c_str());
  env.CallStaticVoidMethod(coverage_recorder,
                           coverage_recorder_dump_jacoco_coverage,
                           covered_edge_ids_jni, dump_file_str);
  AssertNoException(env);
}
}  // namespace jazzer

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_CoverageMap_initialize(
    JNIEnv *env, jclass cls, jlong counters) {
  ::jazzer::CoverageTracker::Initialize(*env, counters);
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_CoverageMap_registerNewCounters(
    JNIEnv *env, jclass cls, jint old_num_counters, jint new_num_counters) {
  ::jazzer::CoverageTracker::RegisterNewCounters(*env, old_num_counters,
                                                 new_num_counters);
}
