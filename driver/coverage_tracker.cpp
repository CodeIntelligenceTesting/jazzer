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

#include "glog/logging.h"
#include "third_party/jni/jni.h"

extern "C" void __sanitizer_cov_8bit_counters_init(uint8_t *start,
                                                   uint8_t *end);
extern "C" void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg,
                                         const uintptr_t *pcs_end);

constexpr auto kCoverageMapClass =
    "com/code_intelligence/jazzer/runtime/CoverageMap";

namespace jazzer {

CoverageTracker::CoverageTracker(JVM &jvm) : ExceptionPrinter(jvm) {
  auto &env = jvm.GetEnv();
  jclass coverage_map = jvm.FindClass(kCoverageMapClass);
  jfieldID counters_buffer_id =
      jvm.GetStaticFieldID(coverage_map, "mem", "Ljava/nio/ByteBuffer;");
  jobject counters_buffer =
      env.GetStaticObjectField(coverage_map, counters_buffer_id);
  counters_ =
      reinterpret_cast<uint8_t *>(env.GetDirectBufferAddress(counters_buffer));
  if (counters_ == nullptr) {
    throw std::runtime_error("Failed to get coverage map address");
  }
  counters_size_ = env.GetDirectBufferCapacity(counters_buffer);
  if (env.ExceptionOccurred()) {
    LOG(ERROR) << getAndClearException();
    throw std::runtime_error("failed to retrieve Java coverage buffer");
  }
  __sanitizer_cov_8bit_counters_init(counters_, counters_ + counters_size_);

  // libFuzzer requires an array containing the instruction addresses associated
  // with the coverage counters registered above. Given that we are
  // instrumenting Java code, we need to synthesize addresses that are known not
  // to conflict with any valid instruction address in native code. Just like
  // atheris we ensure there are no collisions by using the addresses of an
  // allocated buffer. Note: We intentionally never deallocate the allocations
  // made here as they have static lifetime and we can't guarantee they wouldn't
  // be freed before libFuzzer stops using them.
  fake_instructions_ = new uint32_t[counters_size_];
  std::fill(fake_instructions_, fake_instructions_ + counters_size_, 0);
  // Never deallocated, see above.
  pc_entries_ = new PCTableEntry[counters_size_];
  for (std::size_t i = 0; i < counters_size_; ++i) {
    pc_entries_[i].PC = reinterpret_cast<uintptr_t>(fake_instructions_ + i);
    // We can't use libFuzzer's value profile tracing of caller-callee
    // relationships as it relies on compiler built-ins to retrieve the callee
    // automatically, which does not work with Java methods. We thus don't
    // report any function PCs.
    pc_entries_[i].PCFlags = 0;
  }
  __sanitizer_cov_pcs_init((uintptr_t *)pc_entries_,
                           (uintptr_t *)(pc_entries_ + counters_size_));
}

void CoverageTracker::Clear() {
  std::fill(counters_, counters_ + counters_size_, 0);
}

uint8_t *CoverageTracker::GetCoverageCounters() { return counters_; }
}  // namespace jazzer
