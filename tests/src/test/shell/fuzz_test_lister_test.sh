#!/bin/bash
#
# Copyright 2024 Code Intelligence GmbH
#
# By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
#
# The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
# located in the root directory of the project.
#

set -euf -o pipefail

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

java_rlocationpath=$(echo "$JAVA_EXECPATH" | cut -d/ -f2-)
java=$(rlocation "$java_rlocationpath")
jazzer=$(rlocation "$1")
jazzer_junit=$(rlocation "$2")
classes=$(rlocation "$3")
junit_api=$(rlocation "$4")
junit_engine=$(rlocation "$5")
junit_params=$(rlocation "$6")
junit_platform_commons=$(rlocation "$7")
junit_platform_engine=$(rlocation "$8")
junit_platform_launcher=$(rlocation "$9")

# Copy classes directory as JUnit does not handle symlinks properly.
cp -rL "$classes" "$TEST_TMPDIR"
classes_dir="$TEST_TMPDIR/fuzz_test_lister_test"

stderr="$TEST_TMPDIR/stderr"
$java \
  -cp $jazzer:$jazzer_junit:$classes_dir:$junit_api:$junit_params:$junit_engine:$junit_platform_commons:$junit_platform_engine:$junit_platform_launcher \
  com.code_intelligence.jazzer.Jazzer \
  --list_fuzz_tests= \
  --target_class=should.be.ignored \
  2>&1 \
  | tee "$stderr" || fail "Jazzer did not exit with exit code 0"

[[ $(grep -c "org.example.FuzzTests::fuzz1" "$stderr") == 1 ]] || fail "Could not find \"fuzz1\""
[[ $(grep -c "org.example.FuzzTests::fuzz2" "$stderr") == 1 ]] || fail "Could not find \"fuzz2\""
