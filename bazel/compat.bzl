#
# Copyright 2024 Code Intelligence GmbH
#
# By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
#
# The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
# located in the root directory of the project.
#
# This file also contains code licensed under Apache2 license.
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
