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

def jazzer_dependencies():
    maybe(
        http_archive,
        name = "platforms",
        sha256 = "48a2d8d343863989c232843e01afc8a986eb8738766bfd8611420a7db8f6f0c3",
        urls = [
            "https://mirror.bazel.build/github.com/bazelbuild/platforms/releases/download/0.0.2/platforms-0.0.2.tar.gz",
            "https://github.com/bazelbuild/platforms/releases/download/0.0.2/platforms-0.0.2.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "rules_python",
        sha256 = "b6d46438523a3ec0f3cead544190ee13223a52f6a6765a29eae7b7cc24cc83a0",
        url = "https://github.com/bazelbuild/rules_python/releases/download/0.1.0/rules_python-0.1.0.tar.gz",
    )

    maybe(
        http_archive,
        name = "bazel_common",
        sha256 = "cf607d9004a518d8a9bc959b558ffca730ab26e31ee1a7a36248fb054ca84cb7",
        strip_prefix = "bazel-common-11b744fb848a5c73b7173e8b771bf857b8558c89",
        url = "https://github.com/google/bazel-common/archive/11b744fb848a5c73b7173e8b771bf857b8558c89.zip",
    )

    maybe(
        http_archive,
        name = "bazel_skylib",
        sha256 = "ebdf850bfef28d923a2cc67ddca86355a449b5e4f38b0a70e584dc24e5984aa6",
        strip_prefix = "bazel-skylib-f80bc733d4b9f83d427ce3442be2e07427b2cc8d",
        urls = [
            "https://github.com/bazelbuild/bazel-skylib/archive/f80bc733d4b9f83d427ce3442be2e07427b2cc8d.tar.gz",
            "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/archive/f80bc733d4b9f83d427ce3442be2e07427b2cc8d.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "rules_jvm_external",
        sha256 = "f2b36a098736f8b742f22cb25dfcab5481ef5e3d8cfeb4f52b71f5537fbb8266",
        strip_prefix = "rules_jvm_external-367eb9ae5be8acd5a069b84c4672a2ed1d0bda82",
        url = "https://github.com/bazelbuild/rules_jvm_external/archive/367eb9ae5be8acd5a069b84c4672a2ed1d0bda82.zip",
    )

    maybe(
        http_archive,
        name = "io_bazel_rules_kotlin",
        sha256 = "eeae65f973b70896e474c57aa7681e444d7a5446d9ec0a59bb88c59fc263ff62",
        url = "https://github.com/bazelbuild/rules_kotlin/releases/download/v1.5.0-alpha-3/rules_kotlin_release.tgz",
    )

    maybe(
        http_archive,
        name = "com_google_glog",
        repo_mapping = {"@com_github_gflags_gflags": "@jazzer_com_github_gflags_gflags"},
        sha256 = "9f520a71cc23900757b8da4f620b15cd9e92f89a1ed79fe395dff7cecdaa5b7a",
        strip_prefix = "glog-8d40d7564d4a06d77d707d7c4a50c8b5dc45dd80",
        url = "https://github.com/google/glog/archive/8d40d7564d4a06d77d707d7c4a50c8b5dc45dd80.tar.gz",
    )

    maybe(
        http_archive,
        name = "com_google_absl",
        sha256 = "6ead5ca816dee2052e80ef746ab88e319f7cf40392e9dcc67d56d2d1e0043660",
        strip_prefix = "abseil-cpp-3a2d6572d06709da32a17f053ca1e3c8e2af90df",
        url = "https://github.com/abseil/abseil-cpp/archive/3a2d6572d06709da32a17f053ca1e3c8e2af90df.zip",
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
        sha256 = "5fb512c8c2813df19467180ab6b4ed734fdf84e618f26560659593bc1a746497",
        strip_prefix = "asm-ASM_9_1",
        url = "https://gitlab.ow2.org/asm/asm/-/archive/ASM_9_1/asm-ASM_9_1.tar.gz",
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
        sha256 = "da48fb5ae4ec3ffc659d4de18232aedea99476935f4ce4b0605f2d6aa1dc2553",
        strip_prefix = "jacoco-178d49870056b8a1f8ea6915e804d28b0dda5609",
        url = "https://github.com/jacoco/jacoco/archive/178d49870056b8a1f8ea6915e804d28b0dda5609.tar.gz",
    )

    maybe(
        http_archive,
        name = "jazzer_libfuzzer",
        build_file = "@jazzer//third_party:libFuzzer.BUILD",
        patches = [
            "@jazzer//third_party:libFuzzer-get-covered-pcs.patch",
        ],
        sha256 = "",
        strip_prefix = "llvm-project-jazzer-323a61f95560431042f906f424a23b5ebd5e566c",
        url = "https://github.com/CodeIntelligenceTesting/llvm-project-jazzer/archive/323a61f95560431042f906f424a23b5ebd5e566c.tar.gz",
    )
