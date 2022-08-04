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

#include "fuzz_target_runner.h"

#include <string>
#include <vector>

#include "absl/strings/str_format.h"
#include "gflags/gflags.h"

DEFINE_string(
    target_class, "",
    "The Java class that contains the static fuzzerTestOneInput function");
DEFINE_string(target_args, "",
              "Arguments passed to fuzzerInitialize as a String array. "
              "Separated by space.");

DEFINE_uint32(keep_going, 0,
              "Continue fuzzing until N distinct exception stack traces have"
              "been encountered. Defaults to exit after the first finding "
              "unless --autofuzz is specified.");
DEFINE_bool(dedup, true,
            "Emit a dedup token for every finding. Defaults to true and is "
            "required for --keep_going and --ignore.");
DEFINE_string(
    ignore, "",
    "Comma-separated list of crash dedup tokens to ignore. This is useful to "
    "continue fuzzing before a crash is fixed.");

DEFINE_string(reproducer_path, ".",
              "Path at which fuzzing reproducers are stored. Defaults to the "
              "current directory.");
DEFINE_string(coverage_report, "",
              "Path at which a coverage report is stored when the fuzzer "
              "exits. If left empty, no report is generated (default)");
DEFINE_string(coverage_dump, "",
              "Path at which a coverage dump is stored when the fuzzer "
              "exits. If left empty, no dump is generated (default)");

DEFINE_string(autofuzz, "",
              "Fully qualified reference to a method on the classpath that "
              "should be fuzzed automatically (example: System.out::println). "
              "Fuzzing will continue even after a finding; specify "
              "--keep_going=N to stop after N findings.");
DEFINE_string(autofuzz_ignore, "",
              "Fully qualified class names of exceptions to ignore during "
              "autofuzz. Separated by comma.");
DEFINE_bool(
    fake_pcs, false,
    "Supply synthetic Java program counters to libFuzzer trace hooks to "
    "make value profiling more effective. Enabled by default if "
    "-use_value_profile=1 is specified.");

DECLARE_bool(hooks);

namespace jazzer {
std::vector<std::string> fuzzTargetRunnerFlagsAsDefines() {
  return {
      absl::StrFormat("-Djazzer.target_class=%s", FLAGS_target_class),
      absl::StrFormat("-Djazzer.target_args=%s", FLAGS_target_args),
      absl::StrFormat("-Djazzer.keep_going=%d", FLAGS_keep_going),
      absl::StrFormat("-Djazzer.dedup=%s", FLAGS_dedup ? "true" : "false"),
      absl::StrFormat("-Djazzer.ignore=%s", FLAGS_ignore),
      absl::StrFormat("-Djazzer.reproducer_path=%s", FLAGS_reproducer_path),
      absl::StrFormat("-Djazzer.coverage_report=%s", FLAGS_coverage_report),
      absl::StrFormat("-Djazzer.coverage_dump=%s", FLAGS_coverage_dump),
      absl::StrFormat("-Djazzer.autofuzz=%s", FLAGS_autofuzz),
      absl::StrFormat("-Djazzer.autofuzz_ignore=%s", FLAGS_autofuzz_ignore),
      absl::StrFormat("-Djazzer.hooks=%s", FLAGS_hooks ? "true" : "false"),
      absl::StrFormat("-Djazzer.fake_pcs=%s",
                      FLAGS_fake_pcs ? "true" : "false"),
  };
}
}  // namespace jazzer
