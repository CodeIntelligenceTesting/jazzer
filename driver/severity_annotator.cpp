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

#include "severity_annotator.h"

#include <vector>

#include "absl/strings/str_split.h"
#include "absl/strings/substitute.h"

namespace {
constexpr auto kFuzzerSecurityIssueLow = "FuzzerSecurityIssueLow";
[[maybe_unused]] constexpr auto kFuzzerSecurityIssueMedium =
    "FuzzerSecurityIssueMedium";
[[maybe_unused]] constexpr auto kFuzzerSecurityIssueHigh =
    "FuzzerSecurityIssueHigh";
[[maybe_unused]] constexpr auto kFuzzerSecurityIssueCritical =
    "FuzzerSecurityIssueCritical";

std::map<std::string, std::string> kExceptionToSeverityMarker = {
    {"java.lang.OutOfMemoryError", kFuzzerSecurityIssueLow},
    {"java.lang.StackOverflowError", kFuzzerSecurityIssueLow}};
}  // namespace

namespace jazzer {
std::string AddSeverityMarker(const std::string &stack_trace) {
  std::vector<std::string> lines = absl::StrSplit(stack_trace, '\n');
  if (lines.empty()) return stack_trace;

  std::vector<std::string> first_line_parts = absl::StrSplit(lines[0], ':');
  if (lines.empty()) return stack_trace;

  std::string exception = first_line_parts[0];
  auto it = kExceptionToSeverityMarker.find(exception);
  if (it == kExceptionToSeverityMarker.end()) return stack_trace;
  std::string severity_marker = it->second;
  lines[0] += absl::Substitute(" ($0)", severity_marker);

  return absl::StrJoin(lines, "\n");
}
}  // namespace jazzer
