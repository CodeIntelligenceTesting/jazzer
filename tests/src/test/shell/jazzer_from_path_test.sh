#!/bin/bash
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

# Verify that the Jazzer launcher finds the jar when executed from PATH.


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

# Unpack the release archive to a temporary directory.
jazzer_release="$(rlocation "$1")"
tmp="$(mktemp -d)"
trap 'rm -r "$tmp"' EXIT
# GNU tar on Windows requires --force-local to support colons in archives names,
# macOS tar does not support it.
tar -xzf "$jazzer_release" -C "$tmp" --force-local || tar -xzf "$jazzer_release" -C "$tmp"

# Add the Jazzer launcher to PATH first so that it is picked over host Jazzer
# installations.
PATH="$tmp:$PATH"
export PATH

jazzer --version
