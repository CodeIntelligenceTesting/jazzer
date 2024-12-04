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

#include "jvm_tooling.h"

#if defined(__ANDROID__)
#include <dlfcn.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#elif defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else  // Assume Linux
#include <unistd.h>
#endif

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/str_split.h"
#include "tools/cpp/runfiles/runfiles.h"

std::string FLAGS_cp = ".";
std::string FLAGS_jvm_args;
std::string FLAGS_additional_jvm_args;
std::string FLAGS_agent_path;

#if defined(_WIN32) || defined(_WIN64)
#define ARG_SEPARATOR ";"
constexpr auto kPathSeparator = '\\';
#else
#define ARG_SEPARATOR ":"
constexpr auto kPathSeparator = '/';
#endif

namespace {
constexpr auto kJazzerBazelRunfilesPath =
    "jazzer/src/main/java/com/code_intelligence/jazzer/"
    "jazzer_standalone_deploy.jar";
constexpr auto kJazzerFileName = "jazzer_standalone.jar";

// Returns the absolute path to the current executable. Compared to argv[0],
// this path can always be used to locate the Jazzer JAR next to it, even when
// Jazzer is executed from PATH.
std::string getExecutablePath() {
  char buf[655536];
#if defined(__APPLE__)
  uint32_t buf_size = sizeof(buf);
  uint32_t read_bytes = buf_size - 1;
  bool failed = (_NSGetExecutablePath(buf, &buf_size) != 0);
#elif defined(_WIN32)
  DWORD read_bytes = GetModuleFileNameA(NULL, buf, sizeof(buf));
  bool failed = (read_bytes == 0);
#elif defined(__ANDROID__)
  bool failed = true;
  uint32_t read_bytes = 0;
#else  // Assume Linux
  ssize_t read_bytes = readlink("/proc/self/exe", buf, sizeof(buf));
  bool failed = (read_bytes == -1);
#endif
  if (failed) {
    return "";
  }
  buf[read_bytes] = '\0';
  return {buf};
}

std::string dirFromFullPath(const std::string &path) {
  const auto pos = path.rfind(kPathSeparator);
  if (pos != std::string::npos) {
    return path.substr(0, pos);
  }
  return "";
}

// getInstrumentorAgentPath searches for the fuzzing instrumentation agent and
// returns the location if it is found. Otherwise it calls exit(0).
std::string getInstrumentorAgentPath() {
  // User provided agent location takes precedence.
  if (!FLAGS_agent_path.empty()) {
    if (std::ifstream(FLAGS_agent_path).good()) return FLAGS_agent_path;
    std::cerr << "ERROR: Could not find " << kJazzerFileName << " at \""
              << FLAGS_agent_path << "\"" << std::endl;
    exit(1);
  }

  auto executable_path = getExecutablePath();

  if (!executable_path.empty()) {
    // First check if we are running inside the Bazel tree and use the agent
    // runfile.
    using bazel::tools::cpp::runfiles::Runfiles;
    std::string error;
    std::unique_ptr<Runfiles> runfiles(Runfiles::Create(
        std::string(executable_path), BAZEL_CURRENT_REPOSITORY, &error));
    if (runfiles != nullptr) {
      auto bazel_path = runfiles->Rlocation(kJazzerBazelRunfilesPath);
      if (!bazel_path.empty() && std::ifstream(bazel_path).good())
        return bazel_path;
    }

    // If the agent is not in the bazel path we look next to the jazzer binary.
    const auto dir = dirFromFullPath(executable_path);
    auto agent_path =
        absl::StrFormat("%s%c%s", dir, kPathSeparator, kJazzerFileName);
    if (std::ifstream(agent_path).good()) return agent_path;
  }

  std::cerr << "ERROR: Could not find " << kJazzerFileName
            << ". Please provide the pathname via the --agent_path flag."
            << std::endl;
  exit(1);
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

#if defined(__ANDROID__)
typedef jint (*JNI_CreateJavaVM_t)(JavaVM **, JNIEnv **, void *);
JNI_CreateJavaVM_t LoadAndroidVMLibs() {
  std::cout << "Loading Android libraries" << std::endl;

  void *art_so = nullptr;
  art_so = dlopen("libnativehelper.so", RTLD_NOW);

  if (art_so == nullptr) {
    std::cerr << "Could not find ART library" << std::endl;
    exit(1);
  }

  typedef void *(*JniInvocationCreate_t)();
  JniInvocationCreate_t JniInvocationCreate =
      reinterpret_cast<JniInvocationCreate_t>(
          dlsym(art_so, "JniInvocationCreate"));
  if (JniInvocationCreate == nullptr) {
    std::cout << "JniInvocationCreate is null" << std::endl;
    exit(1);
  }

  void *impl = JniInvocationCreate();
  typedef bool (*JniInvocationInit_t)(void *, const char *);
  JniInvocationInit_t JniInvocationInit =
      reinterpret_cast<JniInvocationInit_t>(dlsym(art_so, "JniInvocationInit"));
  if (JniInvocationInit == nullptr) {
    std::cout << "JniInvocationInit is null" << std::endl;
    exit(1);
  }

  JniInvocationInit(impl, nullptr);

  constexpr char create_jvm_symbol[] = "JNI_CreateJavaVM";
  typedef jint (*JNI_CreateJavaVM_t)(JavaVM **, JNIEnv **, void *);
  JNI_CreateJavaVM_t JNI_CreateArtVM =
      reinterpret_cast<JNI_CreateJavaVM_t>(dlsym(art_so, create_jvm_symbol));
  if (JNI_CreateArtVM == nullptr) {
    std::cout << "JNI_CreateJavaVM is null" << std::endl;
    exit(1);
  }

  return JNI_CreateArtVM;
}
#endif

std::string GetClassPath() {
  // combine class path from command line flags and JAVA_FUZZER_CLASSPATH env
  // variable
  std::string class_path = absl::StrFormat("-Djava.class.path=%s", FLAGS_cp);
  const auto class_path_from_env = std::getenv("JAVA_FUZZER_CLASSPATH");
  if (class_path_from_env) {
    class_path += absl::StrCat(ARG_SEPARATOR, class_path_from_env);
  }

  class_path += absl::StrCat(ARG_SEPARATOR, getInstrumentorAgentPath());
  return class_path;
}

JVM::JVM() {
  std::string class_path = GetClassPath();

  std::vector<JavaVMOption> options;
  options.push_back(JavaVMOption{const_cast<char *>(class_path.c_str())});

#if !defined(__ANDROID__)
  // Set the maximum heap size to a value that is slightly smaller than
  // libFuzzer's default rss_limit_mb. This prevents erroneous oom reports.
  // Note: This approach is deprecated and only kept here for backwards
  //       compatibility. The new approach is to set -rss_limit_mb to a
  //       suitable value based on the JVM heap size when starting libFuzzer
  //       as part of the Jazzer driver.
  options.push_back(JavaVMOption{(char *)"-Xmx1800m"});
  // Preserve and emit stack trace information even on hot paths.
  // This may hurt performance, but also helps find flaky bugs.
  options.push_back(JavaVMOption{(char *)"-XX:-OmitStackTraceInFastThrow"});
  // Optimize GC for high throughput rather than low latency.
  options.push_back(JavaVMOption{(char *)"-XX:+UseParallelGC"});
  // CriticalJNINatives has been removed in JDK 18, EnableDynamicAgentLoading
  // has been added in JDK 9.
  options.push_back(JavaVMOption{(char *)"-XX:+IgnoreUnrecognizedVMOptions"});
  options.push_back(JavaVMOption{(char *)"-XX:+CriticalJNINatives"});
  options.push_back(JavaVMOption{(char *)"-XX:+EnableDynamicAgentLoading"});
#endif

  std::vector<std::string> java_opts_args;
  const char *java_opts = std::getenv("JAVA_OPTS");
  if (java_opts != nullptr) {
    // Mimic the behavior of the JVM when it sees JAVA_TOOL_OPTIONS.
    std::cerr << "Picked up JAVA_OPTS: " << java_opts << std::endl;

    java_opts_args = absl::StrSplit(java_opts, ' ');
    for (const std::string &java_opt : java_opts_args) {
      options.push_back(JavaVMOption{const_cast<char *>(java_opt.c_str())});
    }
  }

  // Add additional jvm options set through command line flags.
  // Keep the vectors in scope as they contain the strings backing the C strings
  // added to options.
  std::vector<std::string> jvm_args;
  if (!FLAGS_jvm_args.empty()) {
    jvm_args = splitEscaped(FLAGS_jvm_args);
    for (const auto &arg : jvm_args) {
      options.push_back(JavaVMOption{const_cast<char *>(arg.c_str())});
    }
  }

  std::vector<std::string> additional_jvm_args;
  if (!FLAGS_additional_jvm_args.empty()) {
    additional_jvm_args = splitEscaped(FLAGS_additional_jvm_args);
    for (const auto &arg : additional_jvm_args) {
      options.push_back(JavaVMOption{const_cast<char *>(arg.c_str())});
    }
  }

#if !defined(__ANDROID__)
  jint jni_version = JNI_VERSION_1_8;
#else
  jint jni_version = JNI_VERSION_1_6;
#endif

  JavaVMInitArgs jvm_init_args = {jni_version, (int)options.size(),
                                  options.data(), JNI_FALSE};

#if !defined(__ANDROID__)
  int ret = JNI_CreateJavaVM(&jvm_, (void **)&env_, &jvm_init_args);
#else
  JNI_CreateJavaVM_t CreateArtVM = LoadAndroidVMLibs();
  if (CreateArtVM == nullptr) {
    std::cerr << "JNI_CreateJavaVM for Android not found" << std::endl;
    exit(1);
  }

  std::cout << "Starting Art VM" << std::endl;
  int ret = CreateArtVM(&jvm_, (JNIEnv_ **)&env_, &jvm_init_args);
#endif

  if (ret != JNI_OK) {
    throw std::runtime_error(
        absl::StrFormat("JNI_CreateJavaVM returned code %d", ret));
  }
}

JNIEnv &JVM::GetEnv() const { return *env_; }

JVM::~JVM() { jvm_->DestroyJavaVM(); }
}  // namespace jazzer
