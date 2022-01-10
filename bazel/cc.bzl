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

load("@fmeum_rules_meta//meta:defs.bzl", "wrap_with_transition")

cc_17_library, _unused_1 = wrap_with_transition(
    native.cc_library,
    {
        "cxxopt": {
            "@platforms//os:windows": ["/std:c++17"],
            "//conditions:default": ["-std=c++17"],
        },
    },
)
