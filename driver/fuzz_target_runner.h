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

#include <jni.h>

#include <string>
#include <vector>

#include "jvm_tooling.h"

namespace jazzer {

enum class RunResult {
  kOk,
  kException,
  kDumpAndContinue,
};

// Invokes the following static methods in the java fuzz target class:
// 1. On construction:
//    - `public static void fuzzerInitialize()`
//    OR
//    - `public static void fuzzerInitialize(String[] args)`
// 2. On every call of Run():
//    - `public static void fuzzerTestOneInput(FuzzedDataProvider data)`
//    OR
//    - `public static void fuzzerTestOneInput(byte[] input)`
// 3. On destruction:
//    - `public static void fuzzerTearDown()`
class FuzzTargetRunner : public ExceptionPrinter {
 private:
  const JVM &jvm_;
  jclass jclass_;
  jmethodID fuzzer_initialize_;
  jmethodID fuzzer_initialize_with_args_;
  jmethodID fuzzer_test_one_input_bytes_;
  jmethodID fuzzer_test_one_input_data_;
  jmethodID fuzzer_tear_down_;
  jclass jazzer_;
  jfieldID last_finding_;
  std::vector<jlong> ignore_tokens_;

  [[nodiscard]] std::string DetectFuzzTargetClass() const;
  [[nodiscard]] jthrowable GetFinding() const;

 public:
  // Initializes the java fuzz target by calling `void fuzzerInitialize(...)`.
  explicit FuzzTargetRunner(
      JVM &jvm, const std::vector<std::string> &additional_target_args = {});

  // Calls the fuzz target tear down function. This can be useful to join any
  // Threads so that the JVM shuts down correctly.
  virtual ~FuzzTargetRunner();

  // Propagate the fuzzer input to the java fuzz target.
  RunResult Run(const uint8_t *data, std::size_t size);

  void DumpReproducer(const uint8_t *data, std::size_t size);
};

}  // namespace jazzer
