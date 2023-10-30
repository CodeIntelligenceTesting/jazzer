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

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_jar")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

def jazzer_dependencies(android = False):
    maybe(
        http_archive,
        name = "platforms",
        sha256 = "3a561c99e7bdbe9173aa653fd579fe849f1d8d67395780ab4770b1f381431d51",
        urls = [
            "https://mirror.bazel.build/github.com/bazelbuild/platforms/releases/download/0.0.7/platforms-0.0.7.tar.gz",
            "https://github.com/bazelbuild/platforms/releases/download/0.0.7/platforms-0.0.7.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "bazel_skylib",
        sha256 = "ade20530fd2d39abb49d537e77d4d873a823649b6061e0bb0c369b34450909d6",
        strip_prefix = "bazel-skylib-8386b9d32bf69dd2d2f92d9ca39582cf6dabeb37",
        # TODO: Return to the next release.
        urls = [
            "https://github.com/bazelbuild/bazel-skylib/archive/8386b9d32bf69dd2d2f92d9ca39582cf6dabeb37.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "rules_kotlin",
        sha256 = "5766f1e599acf551aa56f49dab9ab9108269b03c557496c54acaf41f98e2b8d6",
        url = "https://github.com/bazelbuild/rules_kotlin/releases/download/v1.9.0/rules_kotlin-v1.9.0.tar.gz",
    )

    maybe(
        http_archive,
        name = "rules_jvm_external",
        sha256 = "5061364ad9c53de3d2072975f6c14768f2982bbf4101442306270554b317772e",
        strip_prefix = "rules_jvm_external-f0c92a5aa7a9ea457ec3b89c76c59ff72829d9d7",
        url = "https://github.com/bazelbuild/rules_jvm_external/archive/f0c92a5aa7a9ea457ec3b89c76c59ff72829d9d7.tar.gz",
    )

    maybe(
        http_archive,
        name = "build_bazel_apple_support",
        sha256 = "62cb8c6658739d22986bbe4b025fe9f0f42cce91394096dc85d64b120ccde229",
        url = "https://github.com/bazelbuild/apple_support/releases/download/1.10.1/apple_support.1.10.1.tar.gz",
    )

    maybe(
        http_archive,
        name = "com_google_absl",
        sha256 = "987ce98f02eefbaf930d6e38ab16aa05737234d7afbab2d5c4ea7adbe50c28ed",
        strip_prefix = "abseil-cpp-20230802.1",
        url = "https://github.com/abseil/abseil-cpp/archive/refs/tags/20230802.1.tar.gz",
    )

    maybe(
        http_archive,
        name = "com_github_johnynek_bazel_jar_jar",
        sha256 = "7487df7cf64ef85bdd5ffc6a0aff92c46ff7550a663c41b262d53f9dc90cd53d",
        strip_prefix = "bazel_jar_jar-4e7bf26da8bc8c955578fd8c8a2c763757d344df",
        url = "https://github.com/bazeltools/bazel_jar_jar/archive/4e7bf26da8bc8c955578fd8c8a2c763757d344df.tar.gz",
    )

    maybe(
        http_archive,
        name = "com_github_jhalterman_typetools",
        build_file = Label("//third_party:typetools.BUILD"),
        sha256 = "4e11a613aebb3c35deef58d5d942e44802da1a6c6ef7f127419261f00a0a082c",
        strip_prefix = "typetools-commit-887153d2a9adf032fac9f145594d0a0248618d48",
        url = "https://github.com/CodeIntelligenceTesting/typetools/archive/refs/tags/commit-887153d2a9adf032fac9f145594d0a0248618d48.tar.gz",
    )

    maybe(
        http_archive,
        build_file = Label("//third_party:classgraph.BUILD"),
        name = "com_github_classgraph_classgraph",
        sha256 = "83f3c193e90b77487cfc24fb6f73e9624e7478d9be4f94e2b20a29165a1aa906",
        strip_prefix = "classgraph-classgraph-4.8.162",
        url = "https://github.com/classgraph/classgraph/archive/refs/tags/classgraph-4.8.162.tar.gz",
    )

    maybe(
        http_archive,
        name = "fmeum_rules_jni",
        sha256 = "8ea1e90d5f8ab85a2e267f68e4b7e59d9e27b00de533059ab1d829ece2b8bca0",
        url = "https://github.com/fmeum/rules_jni/releases/download/v0.8.0/rules_jni-0.8.0.tar.gz",
    )

    maybe(
        http_jar,
        name = "net_bytebuddy_byte_buddy_agent",
        sha256 = "f7c60fd229df2b0f4e390f50e0582a23ac1d895645df0d487c54dd67a289800b",
        url = "https://repo1.maven.org/maven2/net/bytebuddy/byte-buddy-agent/1.14.8/byte-buddy-agent-1.14.8.jar",
    )

    maybe(
        http_jar,
        name = "org_ow2_asm_asm",
        sha256 = "3c6fac2424db3d4a853b669f4e3d1d9c3c552235e19a319673f887083c2303a1",
        url = "https://repo1.maven.org/maven2/org/ow2/asm/asm/9.6/asm-9.6.jar",
    )

    maybe(
        http_jar,
        name = "org_ow2_asm_asm_commons",
        sha256 = "7aefd0d5c0901701c69f7513feda765fb6be33af2ce7aa17c5781fc87657c511",
        url = "https://repo1.maven.org/maven2/org/ow2/asm/asm-commons/9.6/asm-commons-9.6.jar",
    )

    maybe(
        http_jar,
        name = "org_ow2_asm_asm_tree",
        sha256 = "c43ecf17b539c777e15da7b5b86553b377e2d39a683de6285567d5283888e7ef",
        url = "https://repo1.maven.org/maven2/org/ow2/asm/asm-tree/9.6/asm-tree-9.6.jar",
    )

    maybe(
        http_jar,
        name = "com_github_jsqlparser_jsqlparser",
        sha256 = "9d25de1d79a669352f0d535daee906c2e35e8162e6894d82ea3f0aad8545655e",
        url = "https://repo1.maven.org/maven2/com/github/jsqlparser/jsqlparser/4.7/jsqlparser-4.7.jar",
    )

    maybe(
        http_jar,
        name = "com_google_errorprone_error_prone_annotations",
        sha256 = "9e6814cb71816988a4fd1b07a993a8f21bb7058d522c162b1de849e19bea54ae",
        url = "https://repo1.maven.org/maven2/com/google/errorprone/error_prone_annotations/2.18.0/error_prone_annotations-2.18.0.jar",
    )

    maybe(
        http_jar,
        name = "com_google_errorprone_error_prone_type_annotations",
        sha256 = "d2ab73bc6807277f7463391504313e47bc3465ab1916339c8e82be633a9ab375",
        url = "https://repo1.maven.org/maven2/com/google/errorprone/error_prone_type_annotations/2.18.0/error_prone_type_annotations-2.18.0.jar",
    )

    maybe(
        http_jar,
        name = "com_google_protobuf_protobuf_java",
        sha256 = "e5655522be1aa5cc1f2f092aa036b0445157f294928eedf1332ac938c7b69686",
        # Keep in sync with com_google_protobuf in WORKSPACE.
        url = "https://repo1.maven.org/maven2/com/google/protobuf/protobuf-java/3.24.4/protobuf-java-3.24.4.jar",
    )

    maybe(
        http_archive,
        name = "jazzer_jacoco",
        build_file = Label("//third_party:jacoco_internal.BUILD"),
        patches = [
            Label("//third_party:jacoco-make-probe-adapter-subclassable.patch"),
            Label("//third_party:jacoco-make-probe-inserter-subclassable.patch"),
            Label("//third_party:jacoco-ignore-offline-instrumentation.patch"),
        ],
        sha256 = "5c72dea2d13eef33a4d972d157186fc12d85149bc042186953efe1be50c220ee",
        strip_prefix = "jacoco-0.8.10",
        url = "https://github.com/jacoco/jacoco/archive/refs/tags/v0.8.10.tar.gz",
    )

    maybe(
        http_archive,
        name = "jazzer_libfuzzer",
        build_file = Label("//third_party:libFuzzer.BUILD"),
        sha256 = "200b32c897b1171824462706f577d7f1d6175da602eccfe570d2dceeac11d490",
        strip_prefix = "llvm-project-jazzer-2023-04-25/compiler-rt/lib/fuzzer",
        url = "https://github.com/CodeIntelligenceTesting/llvm-project-jazzer/archive/refs/tags/2023-04-25.tar.gz",
    )

    if android:
        maybe(
            git_repository,
            name = "jazzer_slicer",
            remote = "https://android.googlesource.com/platform/tools/dexter",
            build_file = "//third_party:slicer.BUILD",
            commit = "0fe35538da107ff48da6e9f9b92b55b014973bf8",
        )
