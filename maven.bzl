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

JAZZER_VERSION = "0.19.0"
JAZZER_COORDINATES = "com.code-intelligence:jazzer:%s" % JAZZER_VERSION
JAZZER_API_COORDINATES = "com.code-intelligence:jazzer-api:%s" % JAZZER_VERSION
JAZZER_JUNIT_COORDINATES = "com.code-intelligence:jazzer-junit:%s" % JAZZER_VERSION

# keep sorted
MAVEN_ARTIFACTS = [
    "org.junit.jupiter:junit-jupiter-api:5.9.0",
    "org.junit.jupiter:junit-jupiter-engine:5.9.0",
    "org.junit.jupiter:junit-jupiter-params:5.9.0",
    "org.junit.platform:junit-platform-commons:jar:1.9.0",
    "org.junit.platform:junit-platform-engine:jar:1.9.0",
    "org.junit.platform:junit-platform-launcher:jar:1.9.0",
    "org.opentest4j:opentest4j:1.2.0",
]

# **WARNING**: These Maven dependencies may have known vulnerabilities that Jazzer is supposed to
# find and are only used in tests. DO NOT USE.
TEST_MAVEN_ARTIFACTS = [
    maven.artifact(testonly = True, *coordinate.split(":"))
    for coordinate in [
        # keep sorted
        "com.alibaba:fastjson:1.2.75",
        "com.beust:klaxon:5.5",
        "com.fasterxml.jackson.core:jackson-core:2.12.1",
        "com.fasterxml.jackson.core:jackson-databind:2.12.1",
        "com.fasterxml.jackson.dataformat:jackson-dataformat-cbor:2.12.1",
        "com.google.code.gson:gson:2.8.6",
        "com.google.truth.extensions:truth-java8-extension:1.1.3",
        "com.google.truth.extensions:truth-liteproto-extension:1.1.3",
        "com.google.truth.extensions:truth-proto-extension:1.1.3",
        "com.google.truth:truth:1.1.3",
        "com.h2database:h2:2.1.212",
        "com.mikesamuel:json-sanitizer:1.2.1",
        "com.unboundid:unboundid-ldapsdk:6.0.3",
        "javax.el:javax.el-api:3.0.1-b06",
        "javax.validation:validation-api:2.0.1.Final",
        "javax.xml.bind:jaxb-api:2.3.1",
        "junit:junit:4.12",
        "org.apache.commons:commons-imaging:1.0-alpha2",
        "org.apache.commons:commons-text:1.9",
        "org.apache.logging.log4j:log4j-api:2.14.1",
        "org.apache.logging.log4j:log4j-core:2.14.1",
        "org.apache.xmlgraphics:batik-anim:1.14",
        "org.apache.xmlgraphics:batik-awt-util:1.14",
        "org.apache.xmlgraphics:batik-bridge:1.14",
        "org.apache.xmlgraphics:batik-css:1.14",
        "org.apache.xmlgraphics:batik-dom:1.14",
        "org.apache.xmlgraphics:batik-gvt:1.14",
        "org.apache.xmlgraphics:batik-parser:1.14",
        "org.apache.xmlgraphics:batik-script:1.14",
        "org.apache.xmlgraphics:batik-svg-dom:1.14",
        "org.apache.xmlgraphics:batik-svggen:1.14",
        "org.apache.xmlgraphics:batik-transcoder:1.14",
        "org.apache.xmlgraphics:batik-util:1.14",
        "org.apache.xmlgraphics:batik-xml:1.14",
        "org.assertj:assertj-core:3.23.1",
        "org.glassfish:javax.el:3.0.1-b06",
        "org.hibernate:hibernate-validator:5.2.4.Final",
        "org.jacoco:org.jacoco.core:0.8.8",
        "org.junit.platform:junit-platform-reporting:1.9.0",
        "org.junit.platform:junit-platform-testkit:1.9.0",
        "org.mockito:mockito-core:5.2.0",
        "org.openjdk.jmh:jmh-core:1.34",
        "org.openjdk.jmh:jmh-generator-annprocess:1.34",
    ]
]
