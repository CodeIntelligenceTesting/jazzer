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


# Run the benchmark given by $TEST_SUITE_LABEL, then get all "stat::number_of_executed_units: 12345"
# lines printed by libFuzzer from the logs for the tests passed in on the command line in the form
# "path/to/pkg/name" and compute statistics.
#
# Requires jq to be installed locally.

cd "$BUILD_WORKSPACE_DIRECTORY" || exit 1
# Remove the -runs limit to collect statistics even if the current run limit is too low.
bazel test "$TEST_SUITE_LABEL" --test_arg=-runs=999999999
echo "$@" \
    | xargs -L1 printf "bazel-testlogs/%s/test.log " \
    | xargs -L1 cat \
    | grep '^stat::number_of_executed_units' \
    | cut -d' ' -f2 \
    | jq -s '{values:sort,minimum:min,maximum:max,average:(add/length),median:(sort|if length%2==1 then.[length/2|floor]else[.[length/2-1,length/2]]|add/2 end)}'
