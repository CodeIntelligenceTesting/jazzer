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

SKIP_ON_MACOS = select({
    "@platforms//os:macos": ["@platforms//:incompatible"],
    "//conditions:default": [],
})

SKIP_ON_WINDOWS = select({
    "@platforms//os:windows": ["@platforms//:incompatible"],
    "//conditions:default": [],
})

LINUX_ONLY = select({
    "@platforms//os:linux": [],
    "//conditions:default": ["@platforms//:incompatible"],
})

ANDROID_ONLY = ["@platforms//os:android"]

MULTI_PLATFORM = select({
    "@platforms//os:macos": [
        "//bazel/platforms:macos_arm64",
        "//bazel/platforms:macos_x86_64",
    ],
    "//conditions:default": [],
})
