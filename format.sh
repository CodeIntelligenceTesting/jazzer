#!/usr/bin/env bash
# Copyright 2023 Code Intelligence GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


set -euo pipefail

# C++ & Java
find -name '*.cpp' -o -name '*.c' -o -name '*.h' -o -name '*.java' | xargs clang-format-14 -i

# Kotlin
# curl -sSLO https://github.com/pinterest/ktlint/releases/download/0.48.0/ktlint && chmod a+x ktlint
ktlint -F "examples/**/*.kt" "sanitizers/**/*.kt" "src/**/*.kt" "tests/**/*.kt" --disabled_rules=package-name

# BUILD files
# go install github.com/bazelbuild/buildtools/buildifier@latest
buildifier -r .

# Licence headers
# go install github.com/google/addlicense@latest
addlicense -c "Code Intelligence GmbH" bazel/ deploy/ docker/ examples/ sanitizers/ src/ tests/ *.bzl
