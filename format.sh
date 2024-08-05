#!/usr/bin/env bash
#
# Copyright 2024 Code Intelligence GmbH
#
# By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
#
# The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
# located in the root directory of the project.
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
    TARGETS_TO_RUN=$(bazel test --config=quiet $(bazel query --config=quiet 'kind(ktlint_test, //...)') | { grep FAILED || true; } | cut -f1 -d' ' | sed -e 's/:ktlint_test/:ktlint_fix/g')
    if [[ -n "${TARGETS_TO_RUN}" ]]; then
        echo "$TARGETS_TO_RUN" | xargs -n 1 bazel run --config=quiet
    fi

    # BUILD files
    bazel run --config=quiet //:buildifier -- -r "$THIS_DIR"
fi
