#!/usr/bin/env bash
# Copyright 2023 Code Intelligence GmbH
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

# Development-only. This script builds the example project against the local version of Jazzer,
# runs its unit and fuzz tests, and compares the results with expected results.

set -e
( cd ../../ &&
 bazel build //...
)

# Update jazzer version used for building this project in the pom.xml
JAZZER_VERSION=$(grep -oP '(?<=JAZZER_VERSION = ")[^"]*' ../../maven.bzl)
# Find line with "<artifactId>jazzer-junit</artifactId>" and replace the version in the next line
sed -i "/<artifactId>jazzer-junit<\/artifactId>/ {n;s/<version>.*<\/version>/<version>$JAZZER_VERSION<\/version>/}" pom.xml

# Add locally-built Jazzer to the Maven repository
./mvnw install:install-file -Dfile=../../bazel-bin/deploy/jazzer-junit-project.jar -DpomFile=../../bazel-bin/deploy/jazzer-junit-pom.xml
./mvnw install:install-file -Dfile=../../bazel-bin/deploy/jazzer-project.jar       -DpomFile=../../bazel-bin/deploy/jazzer-pom.xml
./mvnw install:install-file -Dfile=../../bazel-bin/deploy/jazzer-api-project.jar   -DpomFile=../../bazel-bin/deploy/jazzer-api-pom.xml


## Regression and unit tests
echo "[SPRINGBOOT-JUNIT]: These unit and regression fuzz tests should pass"
./mvnw test -Dtest="JunitSpringWebApplicationTests#unitTestShouldPass+fuzzTestShouldPass"

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
JAZZER_FUZZ=1 ./mvnw test -Dtest="JunitSpringWebApplicationTests#fuzzTestShouldPass"

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

echo "[SPRINGBOOT-JUNIT]: All tests passed"
