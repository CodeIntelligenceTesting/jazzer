#!/bin/bash
#
# Copyright 2024 Code Intelligence GmbH
#
# By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
#
# The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
# located in the root directory of the project.
#

# Verify that instrumentation filter defaults set by @FuzzTest work.

# --- begin runfiles.bash initialization v2 ---
# Copy-pasted from the Bazel Bash runfiles library v2.
set -uo pipefail; f=bazel_tools/tools/bash/runfiles/runfiles.bash
source "${RUNFILES_DIR:-/dev/null}/$f" 2>/dev/null || \
  source "$(grep -sm1 "^$f " "${RUNFILES_MANIFEST_FILE:-/dev/null}" | cut -f2- -d' ')" 2>/dev/null || \
  source "$0.runfiles/$f" 2>/dev/null || \
  source "$(grep -sm1 "^$f " "$0.runfiles_manifest" | cut -f2- -d' ')" 2>/dev/null || \
  source "$(grep -sm1 "^$f " "$0.exe.runfiles_manifest" | cut -f2- -d' ')" 2>/dev/null || \
  { echo>&2 "ERROR: cannot find $f"; exit 1; }; f=; set -e
# --- end runfiles.bash initialization v2 ---

function fail() {
  echo "FAILED: $1"
  exit 1
}

stderr="$TEST_TMPDIR/stderr"

"$(rlocation "$1")" --target_class=com.example.JUnitAgentConfigurationFuzzTest 2>&1 -runs=1 | tee "$stderr" || fail "Jazzer did not exit with exit code 0"

[[ $(grep -c "INFO: Instrumented " "$stderr") == 1 ]] || fail "Expected exactly one instrumented class"
[[ $(grep "INFO: Instrumented " "$stderr" | grep -c -v "INFO: Instrumented com.example.") == 0 ]] || fail "Expected all instrumented classes to be in com.example"
