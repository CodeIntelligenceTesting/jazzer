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

#include "absl/strings/str_format.h"

extern "C" void __sanitizer_cov_8bit_counters_init(uint8_t *start,
                                                   uint8_t *end);
extern "C" void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg,
                                         const uintptr_t *pcs_end);
extern "C" size_t __sanitizer_cov_get_observed_pcs(uintptr_t **pc_entries);

constexpr auto kCoverageMapClass =
    "com/code_intelligence/jazzer/runtime/CoverageMap";
constexpr auto kByteBufferClass = "java/nio/ByteBuffer";
constexpr auto kCoverageRecorderClass =
    "com/code_intelligence/jazzer/instrumentor/CoverageRecorder";

// The initial size of the Java coverage map (512 counters).
constexpr std::size_t kInitialCoverageCountersBufferSize = 1u << 9u;
// The maximum size of the Java coverage map (1,048,576 counters).
// Since the memory for the coverage map needs to be allocated contiguously,
// increasing the maximum size incurs additional memory (but not runtime)
// overhead for all fuzz targets.
constexpr std::size_t kMaxCoverageCountersBufferSize = 1u << 20u;
static_assert(kMaxCoverageCountersBufferSize <=
              std::numeric_limits<jint>::max());

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
uint32_t *CoverageTracker::fake_instructions_ = nullptr;
PCTableEntry *CoverageTracker::pc_entries_ = nullptr;

void CoverageTracker::Setup(JNIEnv &env) {
  if (counters_ != nullptr) {
    throw std::runtime_error(
        "CoverageTracker::Setup must not be called more than once");
  }
  JNINativeMethod coverage_tracker_native_methods[]{
      {(char *)"registerNewCoverageCounters", (char *)"()V",
       (void *)&RegisterNewCoverageCounters},
  };
  jclass coverage_map = env.FindClass(kCoverageMapClass);
  env.RegisterNatives(coverage_map, coverage_tracker_native_methods, 1);

  // libFuzzer requires an array containing the instruction addresses associated
  // with the coverage counters registered above. Given that we are
  // instrumenting Java code, we need to synthesize addresses that are known not
  // to conflict with any valid instruction address in native code. Just like
  // atheris we ensure there are no collisions by using the addresses of an
  // allocated buffer. Note: We intentionally never deallocate the allocations
  // made here as they have static lifetime and we can't guarantee they wouldn't
  // be freed before libFuzzer stops using them.
  constexpr std::size_t counters_size = kMaxCoverageCountersBufferSize;
  counters_ = new uint8_t[counters_size];
  Clear();

  // Never deallocated, see above.
  fake_instructions_ = new uint32_t[counters_size];
  std::fill(fake_instructions_, fake_instructions_ + counters_size, 0);

  // Never deallocated, see above.
  pc_entries_ = new PCTableEntry[counters_size];
  for (std::size_t i = 0; i < counters_size; ++i) {
    pc_entries_[i].PC = reinterpret_cast<uintptr_t>(fake_instructions_ + i);
    // TODO: Label Java PCs corresponding to functions as such.
    pc_entries_[i].PCFlags = 0;
  }

  // Register the first batch of coverage counters.
  RegisterNewCoverageCounters(env, nullptr);
}

void JNICALL CoverageTracker::RegisterNewCoverageCounters(JNIEnv &env,
                                                          jclass cls) {
  jclass coverage_map = env.FindClass(kCoverageMapClass);
  AssertNoException(env);
  jfieldID counters_buffer_id = env.GetStaticFieldID(
      coverage_map, "mem", absl::StrFormat("L%s;", kByteBufferClass).c_str());
  AssertNoException(env);
  jobject counters_buffer =
      env.GetStaticObjectField(coverage_map, counters_buffer_id);
  AssertNoException(env);

  jclass byte_buffer = env.FindClass(kByteBufferClass);
  AssertNoException(env);
  jmethodID byte_buffer_capacity_id =
      env.GetMethodID(byte_buffer, "capacity", "()I");
  AssertNoException(env);
  jint old_counters_buffer_size =
      env.CallIntMethod(counters_buffer, byte_buffer_capacity_id);
  AssertNoException(env);

  jint new_counters_buffer_size;
  if (old_counters_buffer_size == 0) {
    new_counters_buffer_size = kInitialCoverageCountersBufferSize;
  } else {
    new_counters_buffer_size = 2 * old_counters_buffer_size;
    if (new_counters_buffer_size > kMaxCoverageCountersBufferSize) {
      throw std::runtime_error(
          "Maximal size of the coverage counters buffer exceeded");
    }
  }

  jobject new_counters_buffer = env.NewDirectByteBuffer(
      static_cast<void *>(counters_), new_counters_buffer_size);
  AssertNoException(env);
  env.SetStaticObjectField(coverage_map, counters_buffer_id,
                           new_counters_buffer);
  AssertNoException(env);

  // Register only the new second half of the counters buffer with libFuzzer.
  __sanitizer_cov_8bit_counters_init(counters_ + old_counters_buffer_size,
                                     counters_ + new_counters_buffer_size);
  __sanitizer_cov_pcs_init(
      (uintptr_t *)(pc_entries_ + old_counters_buffer_size),
      (uintptr_t *)(pc_entries_ + new_counters_buffer_size));
}

void CoverageTracker::Clear() {
  std::fill(counters_, counters_ + kMaxCoverageCountersBufferSize, 0);
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

std::string CoverageTracker::ComputeCoverage(JNIEnv &env) {
  uintptr_t *covered_pcs;
  size_t num_covered_pcs = __sanitizer_cov_get_observed_pcs(&covered_pcs);
  std::vector<jint> covered_edge_ids{};
  covered_edge_ids.reserve(num_covered_pcs);
  const uintptr_t first_pc = pc_entries_[0].PC;
  std::for_each(covered_pcs, covered_pcs + num_covered_pcs,
                [&covered_edge_ids, first_pc](const uintptr_t pc) {
                  jint edge_id =
                      (pc - first_pc) / sizeof(fake_instructions_[0]);
                  covered_edge_ids.push_back(edge_id);
                });
  delete[] covered_pcs;

  jclass coverage_recorder = env.FindClass(kCoverageRecorderClass);
  AssertNoException(env);
  jmethodID coverage_recorder_compute_file_coverage = env.GetStaticMethodID(
      coverage_recorder, "computeFileCoverage", "([I)Ljava/lang/String;");
  AssertNoException(env);
  jintArray covered_edge_ids_jni = env.NewIntArray(num_covered_pcs);
  AssertNoException(env);
  env.SetIntArrayRegion(covered_edge_ids_jni, 0, num_covered_pcs,
                        covered_edge_ids.data());
  AssertNoException(env);
  auto file_coverage_jni = (jstring)(env.CallStaticObjectMethod(
      coverage_recorder, coverage_recorder_compute_file_coverage,
      covered_edge_ids_jni));
  AssertNoException(env);
  auto file_coverage_cstr = env.GetStringUTFChars(file_coverage_jni, nullptr);
  AssertNoException(env);
  std::string file_coverage(file_coverage_cstr);
  env.ReleaseStringUTFChars(file_coverage_jni, file_coverage_cstr);
  AssertNoException(env);
  return file_coverage;
}
}  // namespace jazzer
