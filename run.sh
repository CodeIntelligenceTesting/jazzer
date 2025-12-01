#!/bin/bash
# Copyright 2025 Code Intelligence GmbH
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

fuzz_test="$1"
configuration="$2"
remaining_args="${@:3}"

java_opts='-Xint \
  -XX:+UnlockDiagnosticVMOptions \
  -XX:ActiveProcessorCount=1 \
  -XX:-BackgroundCompilation \
  -XX:-TieredCompilation \
  -XX:-UseTLAB \
  -XX:+UseSerialGC \
  -XX:-UsePerfData \
  -Xms256m \
  -Xmx256m'

JAVA_COMMAND=java
LD_PRELOAD=''
ASAN_OPTIONS=''
class_path="bazel-bin/tests/${fuzz_test}_deploy.jar:bazel-bin/src/main/java/com/code_intelligence/jazzer/jazzer_standalone_deploy.jar"
extra_args=''
if [[ "$configuration" == *asan* ]]; then
  ASAN_OPTIONS=detect_leaks=0
  LD_PRELOAD='/usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.asan-x86_64.so'
  JAVA_COMMAND='/home/simon/git/jdk/build-plain/linux-x86_64-server-release/images/jdk/bin/java'
  extra_args='--asan -detect_leaks=0'
fi

bazel build //src/main/java/com/code_intelligence/jazzer:jazzer_standalone_deploy.jar "//tests:${fuzz_test}_deploy.jar"
ASAN_OPTIONS=${ASAN_OPTIONS} LD_PRELOAD=${LD_PRELOAD} ${JAVA_COMMAND}  \
   '-cp' "${class_path}" 'com.code_intelligence.jazzer.Jazzer' --target_class=com.example.${fuzz_test} --instrumentation_includes="com.example.${fuzz_test}:java.util.zip.**:org.apache.commons.**" ${extra_args} ${remaining_args}
