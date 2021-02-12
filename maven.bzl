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

load("@rules_jvm_external//:specs.bzl", "maven")

JAZZER_API_VERSION = "0.9.1"
JAZZER_API_COORDINATES = "com.code-intelligence:jazzer-api:%s" % JAZZER_API_VERSION

MAVEN_ARTIFACTS = [
    "org.ow2.asm:asm:9.1",
    "org.ow2.asm:asm-commons:9.1",
    "org.ow2.asm:asm-tree:9.1",
    maven.artifact("junit", "junit", "4.12", testonly = True),
    "org.apache.commons:commons-imaging:1.0-alpha2",
    "com.mikesamuel:json-sanitizer:1.2.1",
    "com.google.code.gson:gson:2.8.6",
    "com.fasterxml.jackson.core:jackson-core:2.12.1",
    "com.fasterxml.jackson.core:jackson-databind:2.12.1",
    "com.fasterxml.jackson.dataformat:jackson-dataformat-cbor:2.12.1",
    "com.alibaba:fastjson:1.2.75",
]
