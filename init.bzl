#
# Copyright 2024 Code Intelligence GmbH
#
# By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
#
# The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
# located in the root directory of the project.
#

"""Dependency initialization utilities."""

load("@bazel_skylib//:workspace.bzl", "bazel_skylib_workspace")
load("@com_github_johnynek_bazel_jar_jar//:jar_jar.bzl", "jar_jar_repositories")
load("@rules_kotlin//kotlin:dependencies.bzl", "kt_download_local_dev_dependencies")
load("@rules_kotlin//kotlin:repositories.bzl", "kotlin_repositories")
load("@fmeum_rules_jni//jni:repositories.bzl", "rules_jni_dependencies")
load("@build_bazel_apple_support//lib:repositories.bzl", "apple_support_dependencies")

def jazzer_init():
    bazel_skylib_workspace()
    kt_download_local_dev_dependencies()
    kotlin_repositories()
    native.register_toolchains("@jazzer//bazel/toolchains:kotlin_toolchain")
    jar_jar_repositories()
    rules_jni_dependencies()
    apple_support_dependencies()
