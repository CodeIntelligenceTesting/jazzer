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

#include <rules_jni.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

#include "absl/strings/match.h"
#include "absl/strings/str_format.h"
#include "fuzz_target_runner.h"
#include "gflags/gflags.h"
#include "glog/logging.h"
#include "jvm_tooling.h"

using namespace std::string_literals;

// Defined by glog
DECLARE_bool(log_prefix);

// Defined in libfuzzer_callbacks.cpp
DECLARE_bool(fake_pcs);

// Defined in jvm_tooling.cpp
DECLARE_string(id_sync_file);

// Defined in fuzz_target_runner.cpp
DECLARE_string(coverage_report);

// This symbol is defined by sanitizers if linked into Jazzer or in
// sanitizer_symbols.cpp if no sanitizer is used.
extern "C" void __sanitizer_set_death_callback(void (*)());

// We apply a patch to libFuzzer to make it call this function instead of
// __sanitizer_set_death_callback to pass us the death callback.
extern "C" [[maybe_unused]] void __jazzer_set_death_callback(
    void (*callback)()) {
  jazzer::AbstractLibfuzzerDriver::libfuzzer_print_crashing_input_ = callback;
  __sanitizer_set_death_callback(callback);
}

namespace {
char *additional_arg;
std::vector<char *> modified_argv;

std::string GetNewTempFilePath() {
  auto temp_dir = std::filesystem::temp_directory_path();

  std::string temp_filename_suffix(32, '\0');
  std::random_device rng;
  std::uniform_int_distribution<short> dist(0, 'z' - 'a');
  std::generate_n(temp_filename_suffix.begin(), temp_filename_suffix.length(),
                  [&rng, &dist] { return static_cast<char>('a' + dist(rng)); });

  auto temp_path = temp_dir / ("jazzer-" + temp_filename_suffix);
  if (std::filesystem::exists(temp_path))
    throw std::runtime_error("Random temp file path exists: " +
                             temp_path.string());
  return temp_path.string();
}
}  // namespace

namespace jazzer {
// A libFuzzer-registered callback that outputs the crashing input, but does
// not include a stack trace.
void (*AbstractLibfuzzerDriver::libfuzzer_print_crashing_input_)() = nullptr;

AbstractLibfuzzerDriver::AbstractLibfuzzerDriver(
    int *argc, char ***argv, const std::string &usage_string) {
  gflags::SetUsageMessage(usage_string);
  // Disable glog log prefixes to mimic libFuzzer output.
  FLAGS_log_prefix = false;
  google::InitGoogleLogging((*argv)[0]);
  rules_jni_init((*argv)[0]);

  auto argv_start = *argv;
  auto argv_end = *argv + *argc;

  if (std::find(argv_start, argv_end, "-use_value_profile=1"s) != argv_end) {
    FLAGS_fake_pcs = true;
  }

  // All libFuzzer flags start with a single dash, our arguments all start with
  // a double dash. We can thus filter out the arguments meant for gflags by
  // taking only those with a leading double dash.
  std::vector<char *> our_args = {*argv_start};
  std::copy_if(
      argv_start, argv_end, std::back_inserter(our_args),
      [](const auto arg) { return absl::StartsWith(std::string(arg), "--"); });
  int our_argc = our_args.size();
  char **our_argv = our_args.data();
  // Let gflags consume its flags, but keep them in the argument list in case
  // libFuzzer forwards the command line (e.g. with -jobs or -minimize_crash).
  gflags::ParseCommandLineFlags(&our_argc, &our_argv, false);

  if (std::any_of(argv_start, argv_end, [](const std::string_view &arg) {
        return absl::StartsWith(arg, "-fork=") ||
               absl::StartsWith(arg, "-jobs=") ||
               absl::StartsWith(arg, "-merge=");
      })) {
    if (!FLAGS_coverage_report.empty()) {
      LOG(WARNING) << "WARN: --coverage_report does not support parallel "
                      "fuzzing and has been disabled";
      FLAGS_coverage_report = "";
    }
    if (FLAGS_id_sync_file.empty()) {
      // Create an empty temporary file used for coverage ID synchronization and
      // pass its path to the agent in every child process. This requires adding
      // the argument to argv for it to be picked up by libFuzzer, which then
      // forwards it to child processes.
      FLAGS_id_sync_file = GetNewTempFilePath();
      std::string new_arg =
          absl::StrFormat("--id_sync_file=%s", FLAGS_id_sync_file);
      // This argument can be accessed by libFuzzer at any (later) time and thus
      // cannot be safely freed by us.
      additional_arg = strdup(new_arg.c_str());
      modified_argv = std::vector<char *>(argv_start, argv_end);
      modified_argv.push_back(additional_arg);
      // Terminate modified_argv.
      modified_argv.push_back(nullptr);
      // Modify argv and argc for libFuzzer. modified_argv must not be changed
      // after this point.
      *argc += 1;
      *argv = modified_argv.data();
      argv_start = *argv;
      argv_end = *argv + *argc;
    }
    // Creates the file, truncating it if it exists.
    std::ofstream touch_file(FLAGS_id_sync_file, std::ios_base::trunc);

    auto cleanup_fn = [] {
      try {
        std::filesystem::remove(std::filesystem::path(FLAGS_id_sync_file));
      } catch (...) {
        // We should not throw exceptions during shutdown.
      }
    };
    std::atexit(cleanup_fn);
  }

  initJvm(*argv_start);
}

void AbstractLibfuzzerDriver::initJvm(const std::string &executable_path) {
  jvm_ = std::make_unique<jazzer::JVM>(executable_path);
}

LibfuzzerDriver::LibfuzzerDriver(int *argc, char ***argv)
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
