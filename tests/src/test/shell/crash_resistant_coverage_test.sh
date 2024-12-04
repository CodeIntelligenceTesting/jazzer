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

# This test verifies that Jazzer's --nohook mode can be used to measure code coverage using the
# JaCoCo agent.
# It loosely follows the OSS-Fuzz merge logic, which is the most important user of this feature:
# https://github.com/google/oss-fuzz/blob/b8ef6a216dc592f4f491daa35c815b14260315c0/infra/base-images/base-runner/coverage#L181
# The use of libFuzzer's -merge feature should allow coverage collection to proceed through crashing
# inputs, which is also verified by this test.

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


class_dump_dir=$TEST_TMPDIR/classes
mkdir -p "$class_dump_dir"
exec_file=$TEST_TMPDIR/jacoco.exec
excludes='com.code_intelligence.jazzer.**\:com.sun.tools.attach.**\:sun.tools.attach.**\:sun.jvmstat.**'
jacoco_args="destfile=$exec_file,classdumpdir=$class_dump_dir,excludes=$excludes"

corpus_dummy=$TEST_TMPDIR/corpus
mkdir -p "$corpus_dummy"
"$(rlocation jazzer/launcher/jazzer)" \
  --cp="$(rlocation jazzer/tests/CrashResistantCoverageTarget_deploy.jar)" \
  --target_class=com.example.CrashResistantCoverageTarget \
  -merge=1 -timeout=100 --nohooks \
  "--additional_jvm_args=-javaagent\\:$(rlocation jacocoagent/file/jacocoagent.jar)=${jacoco_args}" \
  "$corpus_dummy" \
  "$(rlocation jazzer/tests/src/test/data/crash_resistant_coverage_test/crashing_seeds)" \
  "$(rlocation jazzer/tests/src/test/data/crash_resistant_coverage_test/new_coverage_seeds)"

[[ -e $exec_file ]] || fail "JaCoCo .exec file does not exist"
[[ -s $exec_file ]] || fail "JaCoCo .exec file is empty"

# Available under bazel-testlogs/tests/crash_resistant_coverage_test/test.outputs after the test.
xml_report=$TEST_UNDECLARED_OUTPUTS_DIR/report.xml
java -jar "$(rlocation jacococli/file/jacococli.jar)" report "$exec_file" \
    --xml "$xml_report" \
    --classfiles "$class_dump_dir"

# Verify that no unexpected class is contained in the report.
grep -o -P '<class name="(?!com\/example\/CrashResistantCoverageTarget)[^"]*"' "$xml_report" && fail "Unexpected class contained in coverage report"

# Verify that fuzzerTestOneInput and someFunction are fully covered by matching the opening <method>
# tag and a child <counter> tag - (?:[^<]|<[^\/]).* matches everything but </, so there can't be a
# </method> between the two.
# Similarly, verify that <init> isn't covered as the default constructor is never invoked.
cat "$xml_report"
grep -q -P '\Q<method name="&lt;init&gt;" desc="()V" line="21">\E(?:[^<]|<[^\/])*\Q<counter type="LINE" missed="1" covered="0"/>\E' "$xml_report" || fail "<init> has been covered"
grep -q -P '\Q<method name="fuzzerTestOneInput" desc="([B)V" line="23">\E(?:[^<]|<[^\/])*\Q<counter type="LINE" missed="0" covered="5"/>\E' "$xml_report" || fail "fuzzerTestOneInput hasn't been covered"
grep -q -P '\Q<method name="someFunction" desc="()V" line="35">\E(?:[^<]|<[^\/])*\Q<counter type="LINE" missed="0" covered="3"/>\E' "$xml_report" || fail "someFunction hasn't been covered"
