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

#include "libfuzzer_driver.h"

#include <string>
#include <vector>

#include "absl/strings/match.h"
#include "coverage_tracker.h"
#include "driver/libfuzzer_callbacks.h"
#include "fuzz_target_runner.h"
#include "gflags/gflags.h"
#include "glog/logging.h"
#include "signal_handler.h"

using namespace std::string_literals;

DEFINE_bool(hooks, true,
            "Use JVM hooks to provide coverage information to the fuzzer. The "
            "fuzzer uses the coverage information to perform smarter input "
            "selection and mutation. If set to false no "
            "coverage information will be processed. This can be useful for "
            "running a regression test on non-instrumented bytecode.");

// Defined by glog
DECLARE_bool(log_prefix);

// Defined in libfuzzer_callbacks.cpp
DECLARE_bool(fake_pcs);

extern "C" void __real___sanitizer_set_death_callback(void (*callback)());

// We use the linker opt -Wl,--wrap=__sanitizer_set_death_callback to wrap the
// symbol defined by sanitizers_common to receive libFuzzer's death callback.
extern "C" void __wrap___sanitizer_set_death_callback(void (*callback)()) {
  jazzer::AbstractLibfuzzerDriver::libfuzzer_print_crashing_input_ = callback;
  __real___sanitizer_set_death_callback(callback);
}

namespace jazzer {
// A libFuzzer-registered callback that outputs the crashing input, but does
// not include a stack trace.
void (*AbstractLibfuzzerDriver::libfuzzer_print_crashing_input_)() = nullptr;

AbstractLibfuzzerDriver::AbstractLibfuzzerDriver(
    const int argc, char **argv, const std::string &usage_string) {
  gflags::SetUsageMessage(usage_string);
  // Disable glog log prefixes to mimic libFuzzer output.
  FLAGS_log_prefix = false;
  google::InitGoogleLogging(argv[0]);

  auto argv_start = argv;
  auto argv_end = argv + argc;

  if (std::find(argv_start, argv_end, "-use_value_profile=1"s) != argv_end) {
    FLAGS_fake_pcs = true;
  }

  // All libFuzzer flags start with a single dash, our arguments all start with
  // a double dash. We can thus filter out the arguments meant for gflags by
  // taking only those with a leading double dash.
  std::vector<char *> our_args = {argv[0]};
  std::copy_if(
      argv_start, argv_end, std::back_inserter(our_args),
      [](const auto arg) { return absl::StartsWith(std::string(arg), "--"); });
  int our_argc = our_args.size();
  char **our_argv = our_args.data();
  // Let gflags consume its flags, but keep them in the argument list in case
  // libFuzzer forwards the command line (e.g. with -jobs or -minimize_crash).
  gflags::ParseCommandLineFlags(&our_argc, &our_argv, false);

  initJvm(argv[0]);
}

void AbstractLibfuzzerDriver::initJvm(const std::string &executable_path) {
  jvm_ = std::make_unique<jazzer::JVM>(executable_path);
  if (FLAGS_hooks) {
    jazzer::registerFuzzerCallbacks(jvm_->GetEnv());
    CoverageTracker::Setup(jvm_->GetEnv());
    // SignalHandler registers its own native methods
    signal_handler_ = std::make_unique<jazzer::SignalHandler>(*jvm_);
    signal_handler_->SetupSignalHandlers();
  }
}

LibfuzzerDriver::LibfuzzerDriver(const int argc, char **argv)
    : AbstractLibfuzzerDriver(argc, argv, getUsageString()) {
  // the FuzzTargetRunner can only be initialized after the fuzzer callbacks
  // have been registered otherwise link errors would occur
  runner_ = std::make_unique<jazzer::FuzzTargetRunner>(*jvm_);
}

std::string LibfuzzerDriver::getUsageString() {
  return R"(Test java fuzz targets using libFuzzer. Usage:
  jazzer --cp=<java_class_path> --target_class=<fuzz_target_class> <libfuzzer_arguments...>)";
}

RunResult LibfuzzerDriver::TestOneInput(const uint8_t *data,
                                        const std::size_t size) {
  // pass the fuzzer input to the java fuzz target
  return runner_->Run(data, size);
}

void LibfuzzerDriver::DumpReproducer(const uint8_t *data, std::size_t size) {
  return runner_->DumpReproducer(data, size);
}

}  // namespace jazzer
