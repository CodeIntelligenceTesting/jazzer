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

#include "jvm_tooling.h"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <utility>
#include <vector>

#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/str_split.h"
#include "gflags/gflags.h"
#include "glog/logging.h"
#include "tools/cpp/runfiles/runfiles.h"

DEFINE_string(cp, ".",
              "the classpath to use for fuzzing. Behaves analogously to java's "
              "-cp (separator is ':' on Linux/macOS and ';' on Windows, escape "
              "it with '\\').");
DEFINE_string(jvm_args, "",
              "arguments passed to the JVM (separator is ':' on Linux/macOS "
              "and ';' on Windows, escape it with '\\')");
DEFINE_string(additional_jvm_args, "",
              "additional arguments passed to the JVM (separator is ':' on "
              "Linux/macOS and ';' on Windows). Use this option to set further "
              "JVM args that should not "
              "interfere with those provided via --jvm_args.");
DEFINE_string(agent_path, "", "location of the fuzzing instrumentation agent");

// Arguments that are passed to the instrumentation agent.
// The instrumentation agent takes arguments in the form
// <option_1>=<option_1_val>,<option_2>=<option_2_val>,... To not expose this
// format to the user the available options are defined here as flags and
// combined during the initialization of the JVM.
DEFINE_string(instrumentation_includes, "",
              "list of glob patterns for classes that will be instrumented for "
              "fuzzing (separator is ':' on Linux/macOS and ';' on Windows)");
DEFINE_string(
    instrumentation_excludes, "",
    "list of glob patterns for classes that will not be instrumented "
    "for fuzzing (separator is ':' on Linux/macOS and ';' on Windows)");

DEFINE_string(custom_hook_includes, "",
              "list of glob patterns for classes that will only be "
              "instrumented using custom hooks (separator is ':' on "
              "Linux/macOS and ';' on Windows)");
DEFINE_string(
    custom_hook_excludes, "",
    "list of glob patterns for classes that will not be instrumented "
    "using custom hooks (separator is ':' on Linux/macOS and ';' on Windows)");
DEFINE_string(custom_hooks, "",
              "list of classes containing custom instrumentation hooks "
              "(separator is ':' on Linux/macOS and ';' on Windows)");
DEFINE_string(disabled_hooks, "",
              "list of hook classes (custom or built-in) that should not be "
              "loaded (separator is ':' on Linux/macOS and ';' on Windows)");
DEFINE_string(
    trace, "",
    "list of instrumentation to perform separated by colon \":\". "
    "Available options are cov, cmp, div, gep, all. These options "
    "correspond to the \"-fsanitize-coverage=trace-*\" flags in clang.");
DEFINE_string(
    id_sync_file, "",
    "path to a file that should be used to synchronize coverage IDs "
    "between parallel fuzzing processes. Defaults to a temporary file "
    "created for this purpose if running in parallel.");
DEFINE_string(
    dump_classes_dir, "",
    "path to a directory in which Jazzer should dump the instrumented classes");

DEFINE_bool(hooks, true,
            "Use JVM hooks to provide coverage information to the fuzzer. The "
            "fuzzer uses the coverage information to perform smarter input "
            "selection and mutation. If set to false no "
            "coverage information will be processed. This can be useful for "
            "running a regression test on non-instrumented bytecode.");

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

#if defined(_WIN32) || defined(_WIN64)
#define ARG_SEPARATOR ";"
constexpr auto kPathSeparator = '\\';
#else
#define ARG_SEPARATOR ":"
constexpr auto kPathSeparator = '/';
#endif

extern "C" [[maybe_unused]] JNIEXPORT jint JNICALL
JNI_OnLoad_jazzer_initialize(JavaVM *vm, void *) {
  return JNI_VERSION_1_8;
}

namespace {
constexpr auto kAgentBazelRunfilesPath = "jazzer/agent/jazzer_agent_deploy.jar";
constexpr auto kAgentFileName = "jazzer_agent_deploy.jar";

std::string_view dirFromFullPath(std::string_view path) {
  const auto pos = path.rfind(kPathSeparator);
  if (pos != std::string_view::npos) {
    return path.substr(0, pos);
  }
  return "";
}

// getInstrumentorAgentPath searches for the fuzzing instrumentation agent and
// returns the location if it is found. Otherwise it calls exit(0).
std::string getInstrumentorAgentPath(std::string_view executable_path) {
  // User provided agent location takes precedence.
  if (!FLAGS_agent_path.empty()) {
    if (std::ifstream(FLAGS_agent_path).good()) return FLAGS_agent_path;
    LOG(ERROR) << "Could not find " << kAgentFileName << " at \""
               << FLAGS_agent_path << "\"";
    exit(1);
  }
  // First check if we are running inside the Bazel tree and use the agent
  // runfile.
  {
    using bazel::tools::cpp::runfiles::Runfiles;
    std::string error;
    std::unique_ptr<Runfiles> runfiles(
        Runfiles::Create(std::string(executable_path), &error));
    if (runfiles != nullptr) {
      auto bazel_path = runfiles->Rlocation(kAgentBazelRunfilesPath);
      if (!bazel_path.empty() && std::ifstream(bazel_path).good())
        return bazel_path;
    }
  }

  // If the agent is not in the bazel path we look next to the jazzer_driver
  // binary.
  const auto dir = dirFromFullPath(executable_path);
  auto agent_path =
      absl::StrFormat("%s%c%s", dir, kPathSeparator, kAgentFileName);
  if (std::ifstream(agent_path).good()) return agent_path;
  LOG(ERROR) << "Could not find " << kAgentFileName
             << ". Please provide "
                "the pathname via the --agent_path flag.";
  exit(1);
}

std::string agentArgsFromFlags() {
  std::vector<std::string> args;
  for (const auto &flag_pair :
       std::vector<std::pair<std::string, const std::string &>>{
           // {<agent option>, <ref to glog flag> }
           {"instrumentation_includes", FLAGS_instrumentation_includes},
           {"instrumentation_excludes", FLAGS_instrumentation_excludes},
           {"custom_hooks", FLAGS_custom_hooks},
           {"disabled_hooks", FLAGS_disabled_hooks},
           {"custom_hook_includes", FLAGS_custom_hook_includes},
           {"custom_hook_excludes", FLAGS_custom_hook_excludes},
           {"trace", FLAGS_trace},
           {"id_sync_file", FLAGS_id_sync_file},
           {"dump_classes_dir", FLAGS_dump_classes_dir},
       }) {
    if (!flag_pair.second.empty()) {
      args.push_back(flag_pair.first + "=" + flag_pair.second);
    }
  }
  return absl::StrJoin(args, ",");
}

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
      absl::StrFormat("-Djazzer.agent_args=%s", agentArgsFromFlags()),
  };
}

// Splits a string at the ARG_SEPARATOR unless it is escaped with a backslash.
// Backslash itself can be escaped with another backslash.
std::vector<std::string> splitEscaped(const std::string &str) {
  // Protect \\ and \<separator> against splitting.
  const std::string BACKSLASH_BACKSLASH_REPLACEMENT =
      "%%JAZZER_BACKSLASH_BACKSLASH_REPLACEMENT%%";
  const std::string BACKSLASH_SEPARATOR_REPLACEMENT =
      "%%JAZZER_BACKSLASH_SEPARATOR_REPLACEMENT%%";
  std::string protected_str =
      absl::StrReplaceAll(str, {{"\\\\", BACKSLASH_BACKSLASH_REPLACEMENT}});
  protected_str = absl::StrReplaceAll(
      protected_str, {{"\\" ARG_SEPARATOR, BACKSLASH_SEPARATOR_REPLACEMENT}});

  std::vector<std::string> parts = absl::StrSplit(protected_str, ARG_SEPARATOR);
  std::transform(parts.begin(), parts.end(), parts.begin(),
                 [&BACKSLASH_SEPARATOR_REPLACEMENT,
                  &BACKSLASH_BACKSLASH_REPLACEMENT](const std::string &part) {
                   return absl::StrReplaceAll(
                       part,
                       {
                           {BACKSLASH_SEPARATOR_REPLACEMENT, ARG_SEPARATOR},
                           {BACKSLASH_BACKSLASH_REPLACEMENT, "\\"},
                       });
                 });

  return parts;
}
}  // namespace

namespace jazzer {

JVM::JVM(std::string_view executable_path, std::string_view seed) {
  // combine class path from command line flags and JAVA_FUZZER_CLASSPATH env
  // variable
  std::string class_path = absl::StrFormat("-Djava.class.path=%s", FLAGS_cp);
  const auto class_path_from_env = std::getenv("JAVA_FUZZER_CLASSPATH");
  if (class_path_from_env) {
    class_path += absl::StrCat(ARG_SEPARATOR, class_path_from_env);
  }
  class_path +=
      absl::StrCat(ARG_SEPARATOR, getInstrumentorAgentPath(executable_path));
  LOG(INFO) << "got class path " << class_path;

  std::vector<JavaVMOption> options;
  options.push_back(
      JavaVMOption{.optionString = const_cast<char *>(class_path.c_str())});
  // Set the maximum heap size to a value that is slightly smaller than
  // libFuzzer's default rss_limit_mb. This prevents erroneous oom reports.
  options.push_back(JavaVMOption{.optionString = (char *)"-Xmx1800m"});
  options.push_back(JavaVMOption{.optionString = (char *)"-enableassertions"});
  // Preserve and emit stack trace information even on hot paths.
  // This may hurt performance, but also helps find flaky bugs.
  options.push_back(
      JavaVMOption{.optionString = (char *)"-XX:-OmitStackTraceInFastThrow"});
  // Optimize GC for high throughput rather than low latency.
  options.push_back(JavaVMOption{.optionString = (char *)"-XX:+UseParallelGC"});
  options.push_back(
      JavaVMOption{.optionString = (char *)"-XX:+CriticalJNINatives"});
  // Forward libFuzzer's random seed so that Jazzer hooks can base their
  // mutations on it.
  std::string seed_property = absl::StrFormat("-Djazzer.seed=%s", seed);
  options.push_back(
      JavaVMOption{.optionString = const_cast<char *>(seed_property.c_str())});

  std::vector<std::string> fuzz_target_runner_defines =
      fuzzTargetRunnerFlagsAsDefines();
  for (const auto &define : fuzz_target_runner_defines) {
    options.push_back(
        JavaVMOption{.optionString = const_cast<char *>(define.c_str())});
  }

  // Add additional JVM options set through JAVA_OPTS.
  std::vector<std::string> java_opts_args;
  const char *java_opts = std::getenv("JAVA_OPTS");
  if (java_opts != nullptr) {
    // Mimic the behavior of the JVM when it sees JAVA_TOOL_OPTIONS.
    std::cerr << "Picked up JAVA_OPTS: " << java_opts << std::endl;
    java_opts_args = absl::StrSplit(java_opts, ' ');
    for (const std::string &java_opt : java_opts_args) {
      options.push_back(
          JavaVMOption{.optionString = const_cast<char *>(java_opt.c_str())});
    }
  }

  // add additional jvm options set through command line flags
  std::vector<std::string> jvm_args;
  if (!FLAGS_jvm_args.empty()) {
    jvm_args = splitEscaped(FLAGS_jvm_args);
  }
  for (const auto &arg : jvm_args) {
    options.push_back(
        JavaVMOption{.optionString = const_cast<char *>(arg.c_str())});
  }
  std::vector<std::string> additional_jvm_args;
  if (!FLAGS_additional_jvm_args.empty()) {
    additional_jvm_args = splitEscaped(FLAGS_additional_jvm_args);
  }
  for (const auto &arg : additional_jvm_args) {
    options.push_back(
        JavaVMOption{.optionString = const_cast<char *>(arg.c_str())});
  }

  JavaVMInitArgs jvm_init_args = {.version = JNI_VERSION_1_8,
                                  .nOptions = (int)options.size(),
                                  .options = options.data(),
                                  .ignoreUnrecognized = JNI_FALSE};

  auto ret = JNI_CreateJavaVM(&jvm_, (void **)&env_, &jvm_init_args);
  if (ret != JNI_OK) {
    throw std::runtime_error(
        absl::StrFormat("JNI_CreateJavaVM returned code %d", ret));
  }
}

JNIEnv &JVM::GetEnv() const { return *env_; }

JVM::~JVM() { jvm_->DestroyJavaVM(); }
}  // namespace jazzer
