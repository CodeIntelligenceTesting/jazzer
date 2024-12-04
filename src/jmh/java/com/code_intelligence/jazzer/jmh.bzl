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

JMH_TEST_ARGS = [
    # Fail fast on any exceptions produced by benchmarks.
    "-foe true",
    "-wf 0",
    "-f 1",
    "-wi 0",
    "-i 1",
    "-r 1s",
    "-w 1s",
]
