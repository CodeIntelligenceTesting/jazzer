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

"""Contains the external dependencies required to build Jazzer (but not the examples)."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
load("//bazel:local_jdk_libjvm.bzl", "local_jdk_libjvm")

def jazzer_dependencies():
    maybe(
        http_archive,
        name = "platforms",
        sha256 = "079945598e4b6cc075846f7fd6a9d0857c33a7afc0de868c2ccb96405225135d",
        urls = [
            "https://mirror.bazel.build/github.com/bazelbuild/platforms/releases/download/0.0.4/platforms-0.0.4.tar.gz",
            "https://github.com/bazelbuild/platforms/releases/download/0.0.4/platforms-0.0.4.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "bazel_common",
        sha256 = "8b6aebdc095c8448b2f6a72bb8eae4a563891467e2d20c943f21940b1c444e38",
        strip_prefix = "bazel-common-3d0e5005cfcbee836e31695d4ab91b5328ccc506",
        url = "https://github.com/google/bazel-common/archive/3d0e5005cfcbee836e31695d4ab91b5328ccc506.zip",
    )

    maybe(
        http_archive,
        name = "bazel_skylib",
        sha256 = "37fbe6e229f28dfda55d9c9a305235b882a1cf6cff746ce448b8b870ecfdf620",
        strip_prefix = "bazel-skylib-fd75066f159234265efb8f838b056be5a2e00a59",
        urls = [
            "https://github.com/bazelbuild/bazel-skylib/archive/fd75066f159234265efb8f838b056be5a2e00a59.tar.gz",
            "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/archive/fd75066f159234265efb8f838b056be5a2e00a59.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "rules_jvm_external",
        sha256 = "f36441aa876c4f6427bfb2d1f2d723b48e9d930b62662bf723ddfb8fc80f0140",
        strip_prefix = "rules_jvm_external-4.1",
        url = "https://github.com/bazelbuild/rules_jvm_external/archive/4.1.zip",
    )

    maybe(
        http_archive,
        name = "io_bazel_rules_kotlin",
        sha256 = "58edd86f0f3c5b959c54e656b8e7eb0b0becabd412465c37a2078693c2571f7f",
        url = "https://github.com/bazelbuild/rules_kotlin/releases/download/v1.5.0-beta-3/rules_kotlin_release.tgz",
    )

    maybe(
        http_archive,
        name = "com_google_glog",
        repo_mapping = {"@com_github_gflags_gflags": "@jazzer_com_github_gflags_gflags"},
        sha256 = "5a39d51a6058348e6b683f5343a24d94e01c518c7a045101045e301a27efab13",
        strip_prefix = "glog-a4a725d547a6c1329607db50af044c4fa329e07a",
        url = "https://github.com/google/glog/archive/a4a725d547a6c1329607db50af044c4fa329e07a.tar.gz",
    )

    maybe(
        http_archive,
        name = "com_google_absl",
        sha256 = "a2837e9042e4adac18e9bbc25f18c2c5ada0c672bc1bbeb9c8769e98b05c6c4e",
        strip_prefix = "abseil-cpp-60be12ed9822078970f05f3c560324184302df6b",
        url = "https://github.com/abseil/abseil-cpp/archive/60be12ed9822078970f05f3c560324184302df6b.zip",
    )

    maybe(
        http_archive,
        name = "com_github_johnynek_bazel_jar_jar",
        sha256 = "97c5f862482a05f385bd8f9d28a9bbf684b0cf3fae93112ee96f3fb04d34b193",
        strip_prefix = "bazel_jar_jar-171f268569384c57c19474b04aebe574d85fde0d",
        url = "https://github.com/johnynek/bazel_jar_jar/archive/171f268569384c57c19474b04aebe574d85fde0d.tar.gz",
    )

    maybe(
        http_archive,
        build_file = "@jazzer//third_party:asm.BUILD",
        name = "jazzer_ow2_asm",
        sha256 = "7b596cc584b241619911e99c5c96366fccd533b1a50b8720c151c2f74b5915e3",
        strip_prefix = "asm-ASM_9_2",
        url = "https://gitlab.ow2.org/asm/asm/-/archive/ASM_9_2/asm-ASM_9_2.tar.gz",
    )

    maybe(
        http_archive,
        name = "jazzer_com_github_gflags_gflags",
        patches = [
            "@jazzer//third_party:gflags-use-double-dash-args.patch",
        ],
        sha256 = "ce2931dd537eaab7dab78b25bec6136a0756ca0b2acbdab9aec0266998c0d9a7",
        strip_prefix = "gflags-827c769e5fc98e0f2a34c47cef953cc6328abced",
        url = "https://github.com/gflags/gflags/archive/827c769e5fc98e0f2a34c47cef953cc6328abced.tar.gz",
    )

    maybe(
        http_archive,
        name = "jazzer_jacoco",
        build_file = "@jazzer//third_party:jacoco_internal.BUILD",
        patches = [
            "@jazzer//third_party:jacoco-make-probe-adapter-subclassable.patch",
            "@jazzer//third_party:jacoco-make-probe-inserter-subclassable.patch",
        ],
        sha256 = "d764c2c02caf8836a12ac582263a109dcac9c1389d3ddee0548aed1322f6e01c",
        strip_prefix = "jacoco-0.8.7",
        url = "https://github.com/jacoco/jacoco/archive/v0.8.7.tar.gz",
    )

    maybe(
        http_archive,
        name = "jazzer_libfuzzer",
        build_file = "@jazzer//third_party:libFuzzer.BUILD",
        sha256 = "1c6fd44cf6ea5f70f79fba94a86ff3cd010b9e25f2166b7d55143acd21ce6f08",
        strip_prefix = "llvm-project-jazzer-b9c07e9c1e75857901808c13101c909104c413a8",
        url = "https://github.com/CodeIntelligenceTesting/llvm-project-jazzer/archive/b9c07e9c1e75857901808c13101c909104c413a8.tar.gz",
    )

    maybe(
        local_jdk_libjvm,
        name = "jazzer_libjvm",
    )
