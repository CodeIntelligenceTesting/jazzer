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

#include <jni.h>
#include <stdint.h>

#include <mutex>

namespace jazzer {

// The members of this struct are only accessed by libFuzzer.
struct __attribute__((packed)) PCTableEntry {
  [[maybe_unused]] uintptr_t PC, PCFlags;
};

// CountersTracker manages coverage counter arrays and registers them with
// libFuzzer. It handles two separate counter regions:
// - Coverage counters: for bytecode edge coverage (used by CoverageMap)
// - Extra counters: for user APIs like maximize() (used by
// ExtraCountersTracker.java)
class CountersTracker {
 private:
  static uint8_t *coverage_counters_;
  static uint8_t *extra_counters_;
  static std::mutex mutex_;

  // Shared helper to register a counter range with libFuzzer.
  static void RegisterCounterRange(uint8_t *start, uint8_t *end);

 public:
  // For CoverageMap: initialize coverage counters base address.
  static void Initialize(JNIEnv &env, jlong counters);

  // For CoverageMap: register new coverage counters with libFuzzer.
  static void RegisterNewCounters(JNIEnv &env, jint old_num_counters,
                                  jint new_num_counters);

  // For ExtraCountersTracker.java: initialize extra counters base address.
  static void InitializeExtra(JNIEnv &env, jlong counters);

  // For ExtraCountersTracker.java: register extra counters with libFuzzer.
  static void RegisterExtraCounters(JNIEnv &env, jint start_offset,
                                    jint end_offset);
};

}  // namespace jazzer
