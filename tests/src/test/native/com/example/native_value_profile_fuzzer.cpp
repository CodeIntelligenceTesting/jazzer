// Copyright 2024 Code Intelligence GmbH
//
// By downloading, you agree to the Code Intelligence Jazzer Terms and
// Conditions.
//
// The Code Intelligence Jazzer Terms and Conditions are provided in
// LICENSE-JAZZER.txt located in the root directory of the project.

#include <cstdint>
#include <cstring>

#include "com_example_NativeValueProfileFuzzer.h"

// Prevent the compiler from inlining the secret all the way into checkAccess,
// which would make it trivial for the fuzzer to pass the checks.
volatile uint64_t secret = 0xefe4eb93215cb6b0L;

static uint64_t insecureEncrypt(uint64_t input) { return input ^ secret; }

jboolean Java_com_example_NativeValueProfileFuzzer_checkAccess(JNIEnv *, jclass,
                                                               jlong block1,
                                                               jlong block2) {
  if (insecureEncrypt(block1) == 0x9fc48ee64d3dc090L) {
    if (insecureEncrypt(block2) == 0x888a82ff483ad9c2L) {
      return true;
    }
  }
  return false;
}
