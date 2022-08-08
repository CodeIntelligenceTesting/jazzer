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

/*
 * Jazzer's native main function, which:
 * 1. defines default settings for ASan and UBSan;
 * 2. preprocesses the command-line arguments passed to libFuzzer;
 * 3. starts a JVM;
 * 4. passes control to the fuzz target runner.
 */

#include <rules_jni.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#include "absl/strings/match.h"
#include "absl/strings/str_format.h"
#include "absl/strings/strip.h"
#include "driver/fuzz_target_runner.h"
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

// Defined in fuzz_target_runner.cpp
DECLARE_string(coverage_dump);

namespace {
bool is_asan_active = false;
}

extern "C" {
[[maybe_unused]] const char *__asan_default_options() {
  is_asan_active = true;
  // LeakSanitizer is not yet supported as it reports too many false positives
  // due to how the JVM GC works.
  // We use a distinguished exit code to recognize ASan crashes in tests.
  // Also specify abort_on_error=0 explicitly since ASan aborts rather than
  // exits on macOS by default, which would cause our exit code to be ignored.
  return "abort_on_error=0,detect_leaks=0,exitcode=76";
}

[[maybe_unused]] const char *__ubsan_default_options() {
  // We use a distinguished exit code to recognize UBSan crashes in tests.
  // Also specify abort_on_error=0 explicitly since UBSan aborts rather than
  // exits on macOS by default, which would cause our exit code to be ignored.
  return "abort_on_error=0,exitcode=76";
}
}

namespace {
const std::string kUsageMessage =
    R"(Test java fuzz targets using libFuzzer. Usage:
  jazzer --cp=<java_class_path> --target_class=<fuzz_target_class> <libfuzzer_arguments...>)";

std::unique_ptr<::jazzer::JVM> gJvm;

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

int main(int argc, char **argv) {
  gflags::SetUsageMessage(kUsageMessage);
  // Disable glog log prefixes to mimic libFuzzer output.
  FLAGS_log_prefix = false;
  google::InitGoogleLogging(argv[0]);
  rules_jni_init(argv[0]);

  const auto argv_end = argv + argc;

  // Parse libFuzzer flags to determine Jazzer flag defaults before letting
  // gflags parse the command line.
  if (std::find(argv, argv_end, "-use_value_profile=1"s) != argv_end) {
    FLAGS_fake_pcs = true;
  }

  // All libFuzzer flags start with a single dash, our arguments all start with
  // a double dash. We can thus filter out the arguments meant for gflags by
  // taking only those with a leading double dash.
  std::vector<char *> our_args = {*argv};
  std::copy_if(
      argv, argv_end, std::back_inserter(our_args),
      [](const auto arg) { return absl::StartsWith(std::string(arg), "--"); });
  int our_argc = our_args.size();
  char **our_argv = our_args.data();
  // Let gflags consume its flags, but keep them in the argument list in case
  // libFuzzer forwards the command line (e.g. with -jobs or -minimize_crash).
  gflags::ParseCommandLineFlags(&our_argc, &our_argv, false);

  // The potentially modified command line arguments passed to libFuzzer at the
  // end of this function.
  std::vector<char *> modified_argv = std::vector<char *>(argv, argv_end);

  bool spawns_subprocesses = false;
  if (std::any_of(argv, argv_end, [](std::string_view arg) {
        return absl::StartsWith(arg, "-fork=") ||
               absl::StartsWith(arg, "-jobs=") ||
               absl::StartsWith(arg, "-merge=");
      })) {
    spawns_subprocesses = true;
    if (!FLAGS_coverage_report.empty()) {
      LOG(WARNING) << "WARN: --coverage_report does not support parallel "
                      "fuzzing and has been disabled";
      FLAGS_coverage_report = "";
    }
    if (!FLAGS_coverage_dump.empty()) {
      LOG(WARNING) << "WARN: --coverage_dump does not support parallel "
                      "fuzzing and has been disabled";
      FLAGS_coverage_dump = "";
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
      modified_argv.push_back(strdup(new_arg.c_str()));
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

  std::string seed;
  // Search for the last occurence of a "-seed" argument as that is the one that
  // is used by libFuzzer.
  auto seed_pos = std::find_if(
      std::reverse_iterator(argv_end), std::reverse_iterator(argv),
      [](std::string_view arg) { return absl::StartsWith(arg, "-seed="); });
  if (seed_pos != std::reverse_iterator(argv)) {
    // An explicit seed has been provided on the command-line, record its value
    // so that it can be forwarded to the agent.
    seed = absl::StripPrefix(*seed_pos, "-seed=");
  } else {
    // No explicit seed has been set. Since Jazzer hooks might still want to use
    // a seed and we have to ensure that a fuzzing run can be reproduced by
    // setting the seed printed by libFuzzer, we generate a seed for it here so
    // that the two stay in sync.
    unsigned int random_seed = std::random_device()();
    seed = std::to_string(random_seed);
    // Only add the -seed argument to the command line if not running in a mode
    // that spawns subprocesses. These would inherit the same seed, which might
    // make them less effective.
    if (!spawns_subprocesses) {
      std::string seed_arg = "-seed=" + seed;
      // This argument can be accessed by libFuzzer at any (later) time and thus
      // cannot be safely freed by us.
      modified_argv.push_back(strdup(seed_arg.c_str()));
    }
  }
  // Terminate modified_argv.
  int modified_argc = modified_argv.size();
  modified_argv.push_back(nullptr);

  if (is_asan_active) {
    std::cerr << "WARN: Jazzer is not compatible with LeakSanitizer yet. Leaks "
                 "are not reported."
              << std::endl;
  }

  gJvm = std::make_unique<jazzer::JVM>(argv[0], seed);
  return jazzer::StartFuzzer(&gJvm->GetEnv(), modified_argc,
                             modified_argv.data());
}
