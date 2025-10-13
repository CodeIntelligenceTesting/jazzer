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

load("@rules_java//toolchains:remote_java_repository.bzl", "remote_java_repository")

def _remote_jdk8_repos(_):
    remote_java_repository(
        name = "remote_jdk8_linux",
        target_compatible_with = [
            "@platforms//os:linux",
            "@platforms//cpu:x86_64",
        ],
        sha256 = "af194163bd9c870321f06b134f447869daafe6aef5b92b49d15b2fbc03a3b999",
        strip_prefix = "zulu8.88.0.19-ca-jdk8.0.462-linux_x64",
        urls = [
            "https://cdn.azul.com/zulu/bin/zulu8.88.0.19-ca-jdk8.0.462-linux_x64.tar.gz",
        ],
        version = "8",
    )
    remote_java_repository(
        name = "remote_jdk8_macos_aarch64",
        target_compatible_with = [
            "@platforms//os:macos",
            "@platforms//cpu:aarch64",
        ],
        sha256 = "abfb45c587b80646eedc679f5fd1c47f1851fd682a043adf5c46c0f55e4d2321",
        strip_prefix = "zulu8.88.0.19-ca-jdk8.0.462-macosx_aarch64",
        urls = [
            "https://cdn.azul.com/zulu/bin/zulu8.88.0.19-ca-jdk8.0.462-macosx_aarch64.tar.gz",
        ],
        version = "8",
    )
    remote_java_repository(
        name = "remote_jdk8_macos",
        target_compatible_with = [
            "@platforms//os:macos",
            "@platforms//cpu:x86_64",
        ],
        sha256 = "e39adde0283ff1cb5c82193654c15688ea5ea4e6f38336d001c43d81d26c102c",
        strip_prefix = "zulu8.88.0.19-ca-jdk8.0.462-macosx_x64",
        urls = [
            "https://cdn.azul.com/zulu/bin/zulu8.88.0.19-ca-jdk8.0.462-macosx_x64.tar.gz",
        ],
        version = "8",
    )
    remote_java_repository(
        name = "remote_jdk8_linux_aarch64",
        target_compatible_with = [
            "@platforms//os:linux",
            "@platforms//cpu:aarch64",
        ],
        sha256 = "7f3a4f6a24f764259db98c69e759bf7cae95ce957dadd74117ed5d6037fcfcc7",
        strip_prefix = "zulu8.88.0.19-ca-jdk8.0.462-linux_aarch64",
        urls = [
            "https://cdn.azul.com/zulu/bin/zulu8.88.0.19-ca-jdk8.0.462-linux_aarch64.tar.gz",
        ],
        version = "8",
    )
    remote_java_repository(
        name = "remote_jdk8_windows",
        target_compatible_with = [
            "@platforms//os:windows",
            "@platforms//cpu:x86_64",
        ],
        sha256 = "4811dd4bb476f7484d132cb6393ca58344c45d43b9547f4251b15c5b8d1fd580",
        strip_prefix = "zulu8.88.0.19-ca-jdk8.0.462-win_x64",
        urls = [
            "https://cdn.azul.com/zulu/bin/zulu8.88.0.19-ca-jdk8.0.462-win_x64.zip",
        ],
        version = "8",
    )

remote_jdk8_repos = module_extension(_remote_jdk8_repos)
