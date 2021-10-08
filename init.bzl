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

"""Dependency initialization utilities."""

load("@bazel_skylib//:workspace.bzl", "bazel_skylib_workspace")
load("@com_github_johnynek_bazel_jar_jar//:jar_jar.bzl", "jar_jar_repositories")
load("@io_bazel_rules_kotlin//kotlin:dependencies.bzl", "kt_download_local_dev_dependencies")
load("@io_bazel_rules_kotlin//kotlin:repositories.bzl", "kotlin_repositories")
load("@fmeum_rules_jni//jni:repositories.bzl", "rules_jni_dependencies")

def jazzer_init():
    bazel_skylib_workspace()
    kt_download_local_dev_dependencies()
    kotlin_repositories()
    native.register_toolchains("@jazzer//:kotlin_toolchain")
    jar_jar_repositories()
    rules_jni_dependencies()
