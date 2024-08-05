// Copyright 2024 Code Intelligence GmbH
//
// By downloading, you agree to the Code Intelligence Jazzer Terms and
// Conditions.
//
// The Code Intelligence Jazzer Terms and Conditions are provided in
// LICENSE-JAZZER.txt located in the root directory of the project.

#include "com_example_ExampleFuzzerWithNative.h"

#include <cstring>
#include <limits>
#include <string>

// simple function containing a crash that requires coverage and string compare
// instrumentation for the fuzzer to find
__attribute__((optnone)) void parseInternal(const std::string &input) {
  constexpr int bar = std::numeric_limits<int>::max() - 5;
  // Crashes with UBSan.
  if (bar + input[0] == 300) {
    return;
  }
  if (input[0] == 'a' && input[1] == 'b' && input[5] == 'c') {
    if (input.find("secret_in_native_library") != std::string::npos) {
      // Crashes with ASan, whose use-after-free hooks detect
      const char *mem = static_cast<const char *>(malloc(2));
      free((void *)mem);
      [[maybe_unused]] bool foo = memcmp(mem, mem + 1, 1);
    }
  }
}

JNIEXPORT jboolean JNICALL Java_com_example_ExampleFuzzerWithNative_parse(
    JNIEnv *env, jobject o, jstring bytes) {
  const char *input(env->GetStringUTFChars(bytes, nullptr));
  parseInternal(input);
  env->ReleaseStringUTFChars(bytes, input);
  return false;
}
