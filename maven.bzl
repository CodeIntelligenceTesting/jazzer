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

JAZZER_API_VERSION = "0.11.0"
JAZZER_API_COORDINATES = "com.code-intelligence:jazzer-api:%s" % JAZZER_API_VERSION

# **WARNING**: These Maven dependencies have known vulnerabilities and are only used to test that
#              Jazzer finds these issues. DO NOT USE.
MAVEN_ARTIFACTS = [
    "com.alibaba:fastjson:1.2.75",
    "com.beust:klaxon:5.5",
    "com.fasterxml.jackson.core:jackson-core:2.12.1",
    "com.fasterxml.jackson.core:jackson-databind:2.12.1",
    "com.fasterxml.jackson.dataformat:jackson-dataformat-cbor:2.12.1",
    "com.google.code.gson:gson:2.8.6",
    "com.mikesamuel:json-sanitizer:1.2.1",
    "com.unboundid:unboundid-ldapsdk:6.0.3",
    "javax.el:javax.el-api:3.0.1-b06",
    "javax.validation:validation-api:2.0.1.Final",
    "javax.xml.bind:jaxb-api:2.3.1",
    "junit:junit:4.12",
    "org.apache.commons:commons-imaging:1.0-alpha2",
    "org.glassfish:javax.el:3.0.1-b06",
    "org.hibernate:hibernate-validator:5.2.4.Final",
    "org.openjdk.jmh:jmh-core:1.34",
    "org.openjdk.jmh:jmh-generator-annprocess:1.34",
    maven.artifact("org.apache.logging.log4j", "log4j-api", "2.14.1", testonly = True),
    maven.artifact("org.apache.logging.log4j", "log4j-core", "2.14.1", testonly = True),
]
