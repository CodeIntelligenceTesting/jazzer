#!/usr/bin/env sh
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

[ -f "$1" ] || exit 1
JAR="$2/bin/jar"
[ -e "$JAR" ] || exit 1
# List all files in the jar and exclude an allowed list of files.
# Since grep fails if there is no match, ! ... | grep ... fails if there is a
# match.
! "$JAR" tf "$1" | \
  grep -v \
    -e '^com/$' \
    -e '^com/code_intelligence/$' \
    -e '^com/code_intelligence/jazzer/$' \
    -e '^com/code_intelligence/jazzer/junit/' \
    -e '^com/code_intelligence/jazzer/sanitizers/$' \
    -e '^com/code_intelligence/jazzer/sanitizers/Constants.class$' \
    -e '^META-INF/$' \
    -e '^META-INF/MANIFEST.MF$' \
    -e '^META-INF/services/$' \
    -e '^META-INF/services/org.junit.platform.engine.TestEngine$'
