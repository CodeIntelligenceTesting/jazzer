/*
 * Copyright 2021 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "jvm_tooling.h"
#include "third_party/jni/jni.h"

namespace jazzer {

// The members of this struct are only accessed by libFuzzer.
struct __attribute__((packed)) PCTableEntry {
  uintptr_t PC, PCFlags;
};

// CoverageTracker registers an array of 8-bit coverage counters with
// libFuzzer. The array is backed by a MappedByteBuffer on the Java
// side, where it is populated with the actual coverage information.
class CoverageTracker : public ExceptionPrinter {
 private:
  uint8_t *counters_;
  std::size_t counters_size_;

  uint32_t *fake_instructions_;
  PCTableEntry *pc_entries_;

 public:
  // Construct the coverage tracker. If the corresponding java class and method
  // cannot be found it will throw std::runtime_error.
  explicit CoverageTracker(JVM &jvm);

  // Clears the coverage counters array manually. It is cleared automatically
  // by libFuzzer prior to running the fuzz target, so this function is only
  // used in tests.
  void Clear();

  // Returns the address of the coverage counters array.
  uint8_t *GetCoverageCounters();
};
}  // namespace jazzer
