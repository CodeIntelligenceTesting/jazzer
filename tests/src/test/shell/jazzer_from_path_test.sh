#!/bin/bash
#
# Copyright 2024 Code Intelligence GmbH
#
# By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
#
# The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
# located in the root directory of the project.
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
