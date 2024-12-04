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

# --- begin runfiles.bash initialization v3 ---
# Copy-pasted from the Bazel Bash runfiles library v3.
set -uo pipefail; set +e; f=bazel_tools/tools/bash/runfiles/runfiles.bash
source "${RUNFILES_DIR:-/dev/null}/$f" 2>/dev/null || \
  source "$(grep -sm1 "^$f " "${RUNFILES_MANIFEST_FILE:-/dev/null}" | cut -f2- -d' ')" 2>/dev/null || \
  source "$0.runfiles/$f" 2>/dev/null || \
  source "$(grep -sm1 "^$f " "$0.runfiles_manifest" | cut -f2- -d' ')" 2>/dev/null || \
  source "$(grep -sm1 "^$f " "$0.exe.runfiles_manifest" | cut -f2- -d' ')" 2>/dev/null || \
  { echo>&2 "ERROR: cannot find $f"; exit 1; }; f=; set -e
# --- end runfiles.bash initialization v3 ---

# JAZZER_EXECPATH is a path of the form "external/remotejdk_17/bin/java". We need to strip of the
# leading external to get a path we can pass to rlocation.
java_rlocationpath=$(echo "$JAVA_EXECPATH" | cut -d/ -f2-)
java=$(rlocation "$java_rlocationpath")
jazzer=$(rlocation "$JAZZER_RLOCATIONPATH")
[ -f "$jazzer" ] || exit 1
jazzer_version_output=$("$java" -jar "$jazzer" --version 2>&1)
echo "$jazzer_version_output"
echo "$jazzer_version_output" | tr -d '\n' | grep -q '^Jazzer v0.0.0-dev$' || exit 1
