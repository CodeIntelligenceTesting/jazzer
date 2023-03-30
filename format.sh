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
# No need to run in CI as the ktlint_tests will fail if the formatting is wrong.
if [[ "${CI:-0}" == 0 ]]; then
    # Check which ktlint_tests failed and run the corresponding fix targets. This is much faster than
    # running all ktlint_fix targets when e.g. only a few or no .kt files changed.
    # shellcheck disable=SC2046
    TARGETS_TO_RUN=$(bazel test --config=quiet $(bazel query --config=quiet 'kind(ktlint_test, //...)') | { grep FAILED || true; } | cut -f1 -d' ' | sed -e 's/:ktlint_test/:ktlint_fix/g')
    if [[ -n "${TARGETS_TO_RUN}" ]]; then
        echo "$TARGETS_TO_RUN" | xargs -n 1 bazel run --config=quiet
    fi
fi

# BUILD files
# go install github.com/bazelbuild/buildtools/buildifier@latest
buildifier -r .

# Licence headers
# go install github.com/google/addlicense@latest
addlicense -c "Code Intelligence GmbH" bazel/ deploy/ docker/ examples/ sanitizers/ src/ tests/ *.bzl
