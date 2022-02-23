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

#include <memory>
#include <string>

#include "absl/strings/match.h"
#include "fuzz_target_runner.h"
#include "fuzzed_data_provider.h"
#include "jvm_tooling.h"

namespace jazzer {

class AbstractLibfuzzerDriver {
 public:
  AbstractLibfuzzerDriver(int *argc, char ***argv,
                          const std::string &usage_string);

  virtual ~AbstractLibfuzzerDriver() = default;

  virtual RunResult TestOneInput(const uint8_t *data, std::size_t size) = 0;

  // Default value of the libFuzzer -error_exitcode flag.
  static constexpr int kErrorExitCode = 77;

  // A libFuzzer-registered callback that outputs the crashing input, but does
  // not include a stack trace.
  static void (*libfuzzer_print_crashing_input_)();

 protected:
  // wrapper around the running jvm instance
  std::unique_ptr<jazzer::JVM> jvm_;

 private:
  void initJvm(std::string_view executable_path, std::string_view seed);
};

class LibfuzzerDriver : public AbstractLibfuzzerDriver {
 public:
  LibfuzzerDriver(int *argc, char ***argv);

  RunResult TestOneInput(const uint8_t *data, std::size_t size) override;

  ~LibfuzzerDriver() override = default;

  void DumpReproducer(const uint8_t *data, std::size_t size);

 private:
  // initializes the fuzz target and invokes the TestOneInput function
  std::unique_ptr<jazzer::FuzzTargetRunner> runner_;

  static std::string getUsageString();
};

}  // namespace jazzer
