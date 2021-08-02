#!/usr/bin/env bash
# Copyright 2021 Code Intelligence GmbH
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

eval "$@"
# Assert that we either found a crash in java (exit code 77) or an ASan crash
# (exit code 76).
declare -i exit_code=$?
if [ $exit_code -eq 77 ] || [ $exit_code -eq 76 ]
then
  if [ "$(ls "$DEFAULT_CRASH_PREFIX/")" ]; then
    exit 0
  else
    exit 1
  fi
else
  echo "Unexpected exit code: $exit_code"
  exit 1
fi
