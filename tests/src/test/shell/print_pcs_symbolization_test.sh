#!/bin/bash
#
# Copyright 2026 Code Intelligence GmbH
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

# Verify that -print_pcs=1 produces symbolized Java source locations
# instead of meaningless hex addresses.

# --- begin runfiles.bash initialization v2 ---
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

JAZZER="$(rlocation "$1")"
TARGET_JAR="$(rlocation "$2")"
output="$TEST_TMPDIR/output"

# A short burst of runs is enough to discover the target's coverage edges.
"$JAZZER" --cp="$TARGET_JAR" --target_class=com.example.PrintPcsTarget \
    --instrumentation_includes="com.example.**" \
    -print_pcs=1 -runs=10 2>&1 | tee "$output" || true

# Verify at least one NEW_PC line has a symbolized Java source location:
# "in <ClassName>.<method> <path>.java:<line>"
if ! grep -qP 'NEW_PC:.*in \S+\.\S+ \S+\.java:\d+' "$output"; then
  echo "Output was:"
  cat "$output"
  fail "Expected symbolized NEW_PC lines with Java source locations"
fi
