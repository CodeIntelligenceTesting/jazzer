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

#include <jni.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <mutex>
#include <utility>
#include <vector>

#include "absl/strings/str_split.h"
#include "com_code_intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks.h"

namespace {
bool is_using_native_libraries = false;
std::once_flag ignore_list_flag;
std::vector<std::pair<uintptr_t, uintptr_t>> ignore_for_interception_ranges;

/**
 * Adds the address ranges of executable segments of the library lib_name to
 * the ignorelist for C standard library function interception (strcmp, memcmp,
 * ...).
 */
void ignoreLibraryForInterception(const std::string &lib_name) {
  std::ifstream loaded_libs("/proc/self/maps");
  if (!loaded_libs) {
    // This early exit is taken e.g. on macOS, where /proc does not exist.
    return;
  }
  std::string line;
  while (std::getline(loaded_libs, line)) {
    if (!absl::StrContains(line, lib_name)) continue;
    // clang-format off
    // A typical line looks as follows:
    // 7f15356c9000-7f1536367000 r-xp 0020d000 fd:01 19275673         /usr/lib/jvm/java-15-openjdk-amd64/lib/server/libjvm.so
    // clang-format on
    std::vector<std::string> parts =
        absl::StrSplit(line, ' ', absl::SkipEmpty());
    if (parts.size() != 6) {
      std::cout << "ERROR: Invalid format for /proc/self/maps\n"
                << line << std::endl;
      exit(1);
    }
    // Skip non-executable address rang"s.
    if (!absl::StrContains(parts[1], "x")) continue;
    std::string range_str = parts[0];
    std::vector<std::string> range = absl::StrSplit(range_str, "-");
    if (range.size() != 2) {
      std::cout
          << "ERROR: Unexpected address range format in /proc/self/maps line: "
          << range_str << std::endl;
      exit(1);
    }
    std::size_t pos;
    auto start = std::stoull(range[0], &pos, 16);
    if (pos != range[0].size()) {
      std::cout
          << "ERROR: Unexpected address range format in /proc/self/maps line: "
          << range_str << std::endl;
      exit(1);
    }
    auto end = std::stoull(range[1], &pos, 16);
    if (pos != range[0].size()) {
      std::cout
          << "ERROR: Unexpected address range format in /proc/self/maps line: "
          << range_str << std::endl;
      exit(1);
    }
    ignore_for_interception_ranges.emplace_back(start, end);
  }
}

const std::vector<std::string> kLibrariesToIgnoreForInterception = {
    // The launcher executable itself can be treated just like a library.
    "jazzer",           "libjazzer_preload.so",
    "libinstrument.so", "libjava.so",
    "libjimage.so",     "libjli.so",
    "libjvm.so",        "libnet.so",
    "libverify.so",     "libzip.so",
};
}  // namespace

extern "C" [[maybe_unused]] bool __sanitizer_weak_is_relevant_pc(
    void *caller_pc) {
  // If the fuzz target is not using native libraries, calls to strcmp, memcmp,
  // etc. should never be intercepted. The values reported if they were at best
  // duplicate the values received from our bytecode instrumentation and at
  // worst pollute the table of recent compares with string internal to the JDK.
  if (!is_using_native_libraries) return false;
  // If the fuzz target is using native libraries, intercept calls only if they
  // don't originate from those address ranges that are known to belong to the
  // JDK.
  return std::none_of(
      ignore_for_interception_ranges.cbegin(),
      ignore_for_interception_ranges.cend(),
      [caller_pc](const std::pair<uintptr_t, uintptr_t> &range) {
        uintptr_t start;
        uintptr_t end;
        std::tie(start, end) = range;
        auto address = reinterpret_cast<uintptr_t>(caller_pc);
        return start <= address && address <= end;
      });
}

[[maybe_unused]] void
Java_com_code_1intelligence_jazzer_runtime_TraceDataFlowNativeCallbacks_handleLibraryLoad(
    JNIEnv *, jclass) {
  std::call_once(ignore_list_flag, [] {
    // Force std::cout to be fully initialized.
    // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=26123
    static std::ios_base::Init initIostreams;
    std::cout << "INFO: detected a native library load, enabling interception "
                 "for libc functions"
              << std::endl;
    for (const auto &lib_name : kLibrariesToIgnoreForInterception)
      ignoreLibraryForInterception(lib_name);
    // Enable the ignore list after it has been populated since vector is not
    // thread-safe with respect to concurrent writes and reads.
    is_using_native_libraries = true;
  });
}
