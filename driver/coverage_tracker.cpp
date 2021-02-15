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

#include <algorithm>
#include <memory>
#include <stdexcept>

#include "absl/strings/str_format.h"
#include "third_party/jni/jni.h"

extern "C" void __sanitizer_cov_8bit_counters_init(uint8_t *start,
                                                   uint8_t *end);
extern "C" void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg,
                                         const uintptr_t *pcs_end);

constexpr auto kCoverageMapClass =
    "com/code_intelligence/jazzer/runtime/CoverageMap";
constexpr auto kByteBufferClass = "java/nio/ByteBuffer";

// The initial size of the Java coverage map (512 counters).
constexpr std::size_t kInitialCoverageCountersBufferSize = 1u << 9u;
// The maximum size of the Java coverage map (1,048,576 counters).
// Since the memory for the coverage map needs to be allocated contiguously,
// increasing the maximum size incurs additional memory (but not runtime)
// overhead for all fuzz targets.
constexpr std::size_t kMaxCoverageCountersBufferSize = 1u << 20u;
static_assert(kMaxCoverageCountersBufferSize <=
              std::numeric_limits<jint>::max());

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
  jfieldID counters_buffer_id = env.GetStaticFieldID(
      coverage_map, "mem", absl::StrFormat("L%s;", kByteBufferClass).c_str());
  jobject counters_buffer =
      env.GetStaticObjectField(coverage_map, counters_buffer_id);

  jclass byte_buffer = env.FindClass(kByteBufferClass);
  jmethodID byte_buffer_capacity_id =
      env.GetMethodID(byte_buffer, "capacity", "()I");
  jint old_counters_buffer_size =
      env.CallIntMethod(counters_buffer, byte_buffer_capacity_id);

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
  env.SetStaticObjectField(coverage_map, counters_buffer_id,
                           new_counters_buffer);

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
}  // namespace jazzer
