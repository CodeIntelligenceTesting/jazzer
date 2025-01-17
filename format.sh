#!/usr/bin/env bash
#
# Copyright 2024 Code Intelligence GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


set -euo pipefail

THIS_DIR="$(pwd -P)"

# Licence headers
bazel run --config=quiet //:addlicense -- -c "Code Intelligence GmbH" -ignore '**/third_party/**' -ignore '**/.github/**' "$THIS_DIR"

# Java
find "$THIS_DIR" \( -name '*.java' \) -print0 | xargs -0 bazel run --config=quiet //:google-java-format -- --replace

# C++
find "$THIS_DIR" \( -name '*.cpp' -o -name '*.c' -o -name '*.h' \) -print0 | xargs -0 bazel run --config=quiet //:clang-format -- -i

# No need to run in CI as these formatters have corresponding Bazel tests.
if [[ "${CI:-0}" == 0 ]]; then
    # Kotlin
    # Check which ktlint_tests failed and run the corresponding fix targets. This is much faster than
    # running all ktlint_fix targets when e.g. only a few or no .kt files changed.
    # shellcheck disable=SC2046
    TARGETS_TO_RUN=$(bazel test --config=quiet $(bazel query --config=quiet 'kind(ktlint_test, //...)') | { grep FAILED || true; } | cut -f1 -d' ' | sed -e 's/:ktlint_test/:ktlint_fix/g' || true)
    if [[ -n "${TARGETS_TO_RUN}" ]]; then
        echo "$TARGETS_TO_RUN" | xargs -I '{}' -n 1 bazel run --config=quiet {} -- --format
    fi

    # BUILD files
    bazel run --config=quiet //:buildifier -- -r "$THIS_DIR"
fi
