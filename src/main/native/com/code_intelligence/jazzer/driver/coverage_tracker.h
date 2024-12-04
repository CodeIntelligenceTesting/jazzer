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

#include <string>

namespace jazzer {

// The members of this struct are only accessed by libFuzzer.
struct __attribute__((packed)) PCTableEntry {
  [[maybe_unused]] uintptr_t PC, PCFlags;
};

// CoverageTracker registers an array of 8-bit coverage counters with
// libFuzzer. The array is populated from Java using Unsafe.
class CoverageTracker {
 private:
  static uint8_t *counters_;
  static PCTableEntry *pc_entries_;

 public:
  static void Initialize(JNIEnv &env, jlong counters);
  static void RegisterNewCounters(JNIEnv &env, jint old_num_counters,
                                  jint new_num_counters);
};
}  // namespace jazzer
