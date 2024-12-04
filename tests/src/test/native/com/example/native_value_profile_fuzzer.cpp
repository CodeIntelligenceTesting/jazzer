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
