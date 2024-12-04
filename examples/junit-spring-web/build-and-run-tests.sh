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

# Development-only. This script builds the example project against the local version of Jazzer,
# runs its unit and fuzz tests, and compares the results with expected results.

set -e
( cd ../../ &&
 bazel run //deploy:deploy_local
)

## Regression and unit tests
echo "[SPRINGBOOT-JUNIT]: These unit and regression fuzz tests should pass"
./mvnw test -Dtest="JunitSpringWebApplicationTests#unitTestShouldPass+fuzzTestShouldPass" 2>&1 | tee /dev/tty | grep -v "==API STATS=="

echo "[SPRINGBOOT-JUNIT]: This regression fuzz test should fail."
# Temporarily disable exit on error.
set +e
./mvnw test -Dtest="JunitSpringWebApplicationTests#fuzzTestShouldFail"
declare -i exit_code=$?
set -e

# Assert that the test failed with exit code 1.
if [ $exit_code -eq 1 ]
then
  echo "[SPRINGBOOT-JUNIT]: Expected failing fuzz tests: continuing"
else
  echo "[SPRINGBOOT-JUNIT]: Expected exit code 1, but got $exit_code"
  exit 1
fi

## Fuzz tests
echo "[SPRINGBOOT-JUNIT]: This fuzz test should pass"
JAZZER_FUZZ=1 ./mvnw test -Dtest="JunitSpringWebApplicationTests#fuzzTestShouldPass" 2>&1 | tee /dev/tty | grep "==API STATS=="

echo "[SPRINGBOOT-JUNIT]: This fuzz test should fail"
set +e
JAZZER_FUZZ=1 ./mvnw test -Dtest="JunitSpringWebApplicationTests#fuzzTestShouldFail"
declare -i exit_code=$?
set -e

if [ $exit_code -eq 1 ]
then
  echo "[SPRINGBOOT-JUNIT]: Expected failing fuzz tests: continuing"
else
  echo "[SPRINGBOOT-JUNIT]: Expected exit code 1, but got $exit_code"
  exit 1
fi

echo "[SPRINGBOOT-JUNIT]: This fuzz test using autofuzz should fail"
set +e
JAZZER_FUZZ=1 ./mvnw test -Dtest="JunitSpringWebApplicationTests#fuzzTestWithDtoShouldFail"
declare -i exit_code=$?
set -e

if [ $exit_code -eq 1 ]
then
  echo "[SPRINGBOOT-JUNIT]: Expected failing fuzz tests: continuing"
else
  echo "[SPRINGBOOT-JUNIT]: Expected exit code 1, but got $exit_code"
  exit 1
fi

## CLI tests
## Assert transitive JUnit dependencies are specified
assertDependency() {
  if ./mvnw dependency:tree | grep -q "$1"
  then
    echo "[SPRINGBOOT-JUNIT]: Found $1 dependency in project"
  else
    echo "[SPRINGBOOT-JUNIT]: Did not find $1 dependency in project"
    exit 1
  fi
}
assertDependency "org.junit.jupiter:junit-jupiter-api"
assertDependency "org.junit.jupiter:junit-jupiter-params"
assertDependency "org.junit.platform:junit-platform-launcher"

# Only build project and test jars, no need for a fat-jar or test execution
./mvnw jar:jar
./mvnw jar:test-jar

# Extract dependency locations
out=$(./mvnw dependency:build-classpath -DforceStdout)
deps=$(echo "$out" | sed '/^\[/d')

# Directly execute Jazzer without Maven
echo "[SPRINGBOOT-JUNIT]: Direct Jazzer execution of fuzz test should pass"
java -cp "target/*:${deps}" \
  com.code_intelligence.jazzer.Jazzer \
  --target_class=com.example.JunitSpringWebApplicationTests \
  --target_method=fuzzTestShouldPass \
  --instrumentation_includes=com.example.* \
  --custom_hook_includes=com.example.*


echo "[SPRINGBOOT-JUNIT]: Direct Jazzer execution of fuzz test using autofuzz should fail"
set +e
JAZZER_FUZZ=1 java -cp "target/*:${deps}" \
  com.code_intelligence.jazzer.Jazzer \
  --target_class=com.example.JunitSpringWebApplicationTests \
  --target_method=fuzzTestWithDtoShouldFail \
  --instrumentation_includes=com.example.* \
  --custom_hook_includes=com.example.*
declare -i exit_code=$?
set -e

if [ $exit_code -eq 77 ]
then
  echo "[SPRINGBOOT-JUNIT]: Expected failing fuzz tests: continuing"
else
  echo "[SPRINGBOOT-JUNIT]: Expected exit code 77, but got $exit_code"
  exit 1
fi

echo "[SPRINGBOOT-JUNIT]: All tests passed"
