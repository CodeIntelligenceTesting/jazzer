// Copyright 2024 Code Intelligence GmbH
//
// By downloading, you agree to the Code Intelligence Jazzer Terms and
// Conditions.
//
// The Code Intelligence Jazzer Terms and Conditions are provided in
// LICENSE-JAZZER.txt located in the root directory of the project.

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
