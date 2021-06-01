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

#include <fstream>
#include <iostream>
#include <utility>
#include <vector>

#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "gflags/gflags.h"
#include "glog/logging.h"
#include "libfuzzer_callbacks.h"
#include "utils.h"

DEFINE_string(cp, ".",
              "the jvm class path which should include the fuzz target class, "
              "instrumentor "
              "runtime and further dependencies separated by a colon \":\"");
DEFINE_string(jvm_args, "",
              "arguments passed to the jvm separated by semicolon \";\"");
DEFINE_string(additional_jvm_args, "",
              "additional arguments passed to the jvm separated by semicolon "
              "\";\". Use this option to set further JVM args that should not "
              "interfere with those provided via --jvm_args.");
DEFINE_string(agent_path, "", "location of the fuzzing instrumentation agent");

// Arguments that are passed to the instrumentation agent.
// The instrumentation agent takes arguments in the form
// <option_1>=<option_1_val>,<option_2>=<option_2_val>,... To not expose this
// format to the user the available options are defined here as flags and
// combined during the initialization of the JVM.
DEFINE_string(instrumentation_includes, "",
              "list of glob patterns for classes that will be instrumented for "
              "fuzzing. Separated by colon \":\"");
DEFINE_string(instrumentation_excludes, "",
              "list of glob patterns for classes that will not be instrumented "
              "for fuzzing. Separated by colon \":\"");

DEFINE_string(custom_hook_includes, "",
              "list of glob patterns for classes that will only be "
              "instrumented using custom hooks. Separated by colon \":\"");
DEFINE_string(custom_hook_excludes, "",
              "list of glob patterns for classes that will not be instrumented "
              "using custom hooks. Separated by colon \":\"");
DEFINE_string(custom_hooks, "",
              "list of classes containing custom instrumentation hooks. "
              "Separated by colon \":\"");
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

DECLARE_bool(hooks);

namespace {
constexpr auto kInstrumentorAgentBazelDir = "../jazzer/agent";
constexpr auto kAgentFileName = "jazzer_agent_deploy.jar";
constexpr const char kExceptionUtilsClassName[] =
    "com/code_intelligence/jazzer/runtime/ExceptionUtils";
}  // namespace

namespace jazzer {

std::string dirFromFullPath(const std::string &path) {
  const auto pos = path.rfind(kPathSeparator);
  if (pos != std::string::npos) {
    return path.substr(0, pos);
  }
  return "";
}

// getInstrumentorAgentPath searches for the fuzzing instrumentation agent and
// returns the location if it is found. Otherwise it calls exit(0).
std::string getInstrumentorAgentPath(const std::string &executable_path) {
  // User provided agent location takes precedence.
  if (!FLAGS_agent_path.empty()) {
    if (std::ifstream(FLAGS_agent_path).good()) return FLAGS_agent_path;
    LOG(ERROR) << "Could not find " << kAgentFileName << "in \""
               << FLAGS_agent_path << "\"";
    exit(0);
  }
  // First check if we are running inside the Bazel tree and use the agent
  // runfile. This requires a Bazel env variable to be defined as loading an
  // agent from a sibling directory may not be safe in e.g. download folders.
  if (std::getenv("BUILD_WORKING_DIRECTORY") != nullptr) {
    auto bazel_path = absl::StrFormat("%s%c%s", kInstrumentorAgentBazelDir,
                                      kPathSeparator, kAgentFileName);
    if (std::ifstream(bazel_path).good()) return bazel_path;
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
           {"custom_hook_includes", FLAGS_custom_hook_includes},
           {"custom_hook_excludes", FLAGS_custom_hook_excludes},
           {"trace", FLAGS_trace},
           {"id_sync_file", FLAGS_id_sync_file},
       }) {
    if (!flag_pair.second.empty()) {
      args.push_back(flag_pair.first + "=" + flag_pair.second);
    }
  }
  return absl::StrJoin(args, ",");
}

JVM::JVM(const std::string &executable_path) {
  // combine class path from command line flags and JAVA_FUZZER_CLASSPATH env
  // variable
  std::string class_path = absl::StrFormat("-Djava.class.path=%s", FLAGS_cp);
  const auto class_path_from_env = std::getenv("JAVA_FUZZER_CLASSPATH");
  if (class_path_from_env) {
    class_path += absl::StrFormat(":%s", class_path_from_env);
  }
  class_path +=
      absl::StrFormat(":%s", getInstrumentorAgentPath(executable_path));
  LOG(INFO) << "got class path " << class_path;

  std::vector<JavaVMOption> options;
  options.push_back(
      JavaVMOption{.optionString = const_cast<char *>(class_path.c_str())});
  // Set the maximum heap size to a value that is slightly smaller than
  // libFuzzer's default rss_limit_mb. This prevents erroneous oom reports.
  options.push_back(JavaVMOption{.optionString = (char *)"-Xmx2040m"});
  options.push_back(JavaVMOption{.optionString = (char *)"-enableassertions"});
  // Preserve and emit stack trace information even on hot paths.
  // This may hurt performance, but also helps find flaky bugs.
  options.push_back(
      JavaVMOption{.optionString = (char *)"-XX:-OmitStackTraceInFastThrow"});

  // add additional jvm options set through command line flags
  std::vector<std::string> jvm_args;
  if (!FLAGS_jvm_args.empty()) {
    jvm_args = absl::StrSplit(FLAGS_jvm_args, ';');
  }
  for (const auto &arg : jvm_args) {
    options.push_back(
        JavaVMOption{.optionString = const_cast<char *>(arg.c_str())});
  }
  std::vector<std::string> additional_jvm_args;
  if (!FLAGS_additional_jvm_args.empty()) {
    additional_jvm_args = absl::StrSplit(FLAGS_additional_jvm_args, ';');
  }
  for (const auto &arg : additional_jvm_args) {
    options.push_back(
        JavaVMOption{.optionString = const_cast<char *>(arg.c_str())});
  }

  std::string agent_jvm_arg;
  if (FLAGS_hooks) {
    agent_jvm_arg = absl::StrFormat("-javaagent:%s=%s",
                                    getInstrumentorAgentPath(executable_path),
                                    agentArgsFromFlags());
    options.push_back(JavaVMOption{
        .optionString = const_cast<char *>(agent_jvm_arg.c_str())});
  }

  JavaVMInitArgs jvm_init_args = {.version = JNI_VERSION_1_6,
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

jclass JVM::FindClass(std::string class_name) const {
  auto &env = GetEnv();
  std::replace(class_name.begin(), class_name.end(), '.', '/');
  const auto ret = env.FindClass(class_name.c_str());
  if (ret == nullptr) {
    if (env.ExceptionCheck()) {
      env.ExceptionDescribe();
      throw std::runtime_error(
          absl::StrFormat("Could not find class %s", class_name));
    } else {
      throw std::runtime_error(absl::StrFormat(
          "Java class '%s' not found without exception", class_name));
    }
  }
  return ret;
}

jmethodID JVM::GetStaticMethodID(jclass jclass, const std::string &jmethod,
                                 const std::string &signature,
                                 bool is_required) const {
  auto &env = GetEnv();
  const auto ret =
      env.GetStaticMethodID(jclass, jmethod.c_str(), signature.c_str());
  if (ret == nullptr) {
    if (is_required) {
      if (env.ExceptionCheck()) {
        env.ExceptionDescribe();
      }
      throw std::runtime_error(
          absl::StrFormat("Static method '%s' not found", jmethod));
    } else {
      LOG(INFO) << "did not find method " << jmethod << " with signature "
                << signature;
      env.ExceptionClear();
    }
  }
  return ret;
}

jmethodID JVM::GetMethodID(jclass jclass, const std::string &jmethod,
                           const std::string &signature) const {
  auto &env = GetEnv();
  const auto ret = env.GetMethodID(jclass, jmethod.c_str(), signature.c_str());
  if (ret == nullptr) {
    if (env.ExceptionCheck()) {
      env.ExceptionDescribe();
    }
    throw std::runtime_error(absl::StrFormat("Method '%s' not found", jmethod));
  }
  return ret;
}

jfieldID JVM::GetStaticFieldID(jclass class_id, const std::string &field_name,
                               const std::string &type) const {
  auto &env = GetEnv();
  const auto ret =
      env.GetStaticFieldID(class_id, field_name.c_str(), type.c_str());
  if (ret == nullptr) {
    if (env.ExceptionCheck()) {
      env.ExceptionDescribe();
    }
    throw std::runtime_error(
        absl::StrFormat("Field '%s' not found", field_name));
  }
  return ret;
}

ExceptionPrinter::ExceptionPrinter(JVM &jvm)
    : jvm_(jvm),
      string_writer_class_(jvm.FindClass("java/io/StringWriter")),
      string_writer_constructor_(
          jvm.GetMethodID(string_writer_class_, "<init>", "()V")),
      string_writer_to_string_method_(jvm.GetMethodID(
          string_writer_class_, "toString", "()Ljava/lang/String;")),
      print_writer_class_(jvm.FindClass("java/io/PrintWriter")),
      print_writer_constructor_(jvm.GetMethodID(print_writer_class_, "<init>",
                                                "(Ljava/io/Writer;)V")) {
  auto throwable_class = jvm.FindClass("java/lang/Throwable");
  print_stack_trace_method_ = jvm.GetMethodID(
      throwable_class, "printStackTrace", "(Ljava/io/PrintWriter;)V");
  if (FLAGS_hooks) {
    exception_utils_ = jvm.FindClass(kExceptionUtilsClassName);
    compute_dedup_token_method_ = jvm.GetStaticMethodID(
        exception_utils_, "computeDedupToken", "(Ljava/lang/Throwable;)J");
    preprocess_throwable_method_ =
        jvm.GetStaticMethodID(exception_utils_, "preprocessThrowable",
                              "(Ljava/lang/Throwable;)Ljava/lang/Throwable;");
  }
}

// The JNI way of writing:
//    StringWriter stringWriter = new StringWriter();
//    PrintWriter printWriter = new PrintWriter(stringWriter);
//    e.printStackTrace(printWriter);
//    return stringWriter.toString();
std::string ExceptionPrinter::getStackTrace(jthrowable exception) const {
  auto &env = jvm_.GetEnv();
  if (exception == nullptr) {
    return "";
  }

  auto string_writer =
      env.NewObject(string_writer_class_, string_writer_constructor_);
  if (string_writer == nullptr) {
    env.ExceptionDescribe();
    return "";
  }
  auto print_writer = env.NewObject(print_writer_class_,
                                    print_writer_constructor_, string_writer);
  if (print_writer == nullptr) {
    env.ExceptionDescribe();
    return "";
  }

  env.CallVoidMethod(exception, print_stack_trace_method_, print_writer);
  if (env.ExceptionCheck()) {
    env.ExceptionDescribe();
    return "";
  }
  auto exception_string_object = reinterpret_cast<jstring>(
      env.CallObjectMethod(string_writer, string_writer_to_string_method_));
  if (env.ExceptionCheck()) {
    env.ExceptionDescribe();
    return "";
  }

  auto char_pointer = env.GetStringUTFChars(exception_string_object, nullptr);
  std::string exception_string(char_pointer);
  env.ReleaseStringUTFChars(exception_string_object, char_pointer);
  return exception_string;
}

jthrowable ExceptionPrinter::preprocessException(jthrowable exception) const {
  if (exception == nullptr) return nullptr;
  auto &env = jvm_.GetEnv();
  if (!FLAGS_hooks || !preprocess_throwable_method_) return exception;
  auto processed_exception = (jthrowable)(env.CallStaticObjectMethod(
      exception_utils_, preprocess_throwable_method_, exception));
  if (env.ExceptionCheck()) {
    env.ExceptionDescribe();
    return exception;
  }
  return processed_exception;
}

jlong ExceptionPrinter::computeDedupToken(jthrowable exception) const {
  auto &env = jvm_.GetEnv();
  if (!FLAGS_hooks || exception == nullptr ||
      compute_dedup_token_method_ == nullptr)
    return 0;
  const auto dedup_token = env.CallStaticLongMethod(
      exception_utils_, compute_dedup_token_method_, exception);
  if (env.ExceptionCheck()) {
    env.ExceptionDescribe();
    return 0;
  }
  return dedup_token;
}

}  // namespace jazzer
