#!/usr/bin/env sh
# Copyright 2022 Code Intelligence GmbH
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

set -eu

fail() {
  echo "$1"
  exit 1
}

cd "$BUILD_WORKSPACE_DIRECTORY" || fail "BUILD_WORKSPACE_DIRECTORY not found"

JAZZER_COORDINATES=$1

[ -z "${MAVEN_USER+x}" ] && \
  fail "Set MAVEN_USER to the Sonatype OSSRH user"
[ -z "${MAVEN_PASSWORD+x}" ] && \
  fail "Set MAVEN_PASSWORD to the Sonatype OSSRH password"
[ -z "${JAZZER_JAR_PATH+x}" ] && \
  fail "Set JAZZER_JAR_PATH to the absolute path of jazzer.jar obtained from the release GitHub Actions workflow"
[ ! -f "${JAZZER_JAR_PATH}" ] && \
  fail "JAZZER_JAR_PATH does not exist at '$JAZZER_JAR_PATH'"
[ -z "${JAVA_HOME+x}" ] && \
  fail "Set JAVA_HOME to a JDK 8"
JAVA_VERSION=$("$JAVA_HOME"/bin/java -version 2>&1 | head -1 | cut -d'"' -f2)
[ "1" -eq "$(echo "$JAVA_VERSION" | cut -d'.' -f1)" ] &&
  [ "8" -eq "$(echo "$JAVA_VERSION" | cut -d'.' -f2)" ] || \
  fail "JAVA_HOME ('$JAVA_HOME') must point to a JDK 8, is: $JAVA_VERSION"

MAVEN_REPO=https://oss.sonatype.org/service/local/staging/deploy/maven2

# The Jazzer jar itself bundles native libraries for multiple architectures and thus can't be built
# on the local machine. It is obtained from CI and passed in via JAZZER_JAR_PATH.
bazel build --config=maven //deploy:jazzer-docs //deploy:jazzer-sources //deploy:jazzer-pom

JAZZER_DOCS_PATH=$PWD/$(bazel cquery --config=maven --output=files //deploy:jazzer-docs)
JAZZER_SOURCES_PATH=$PWD/$(bazel cquery --config=maven --output=files //deploy:jazzer-sources)
JAZZER_POM_PATH=$PWD/$(bazel cquery --config=maven --output=files //deploy:jazzer-pom)

bazel run --config=maven --define "maven_repo=${MAVEN_REPO}" --define "maven_user=${MAVEN_USER}" \
  --define "maven_password=${MAVEN_PASSWORD}" --define gpg_sign=true \
  //deploy:jazzer-api.publish
bazel run --config=maven @rules_jvm_external//private/tools/java/rules/jvm/external/maven:MavenPublisher -- \
  "$MAVEN_REPO" true "$MAVEN_USER" "$MAVEN_PASSWORD" "$JAZZER_COORDINATES" \
  "$JAZZER_POM_PATH" "$JAZZER_JAR_PATH" "$JAZZER_SOURCES_PATH" "$JAZZER_DOCS_PATH"
bazel run --config=maven --define "maven_repo=${MAVEN_REPO}" --define "maven_user=${MAVEN_USER}" \
  --define "maven_password=${MAVEN_PASSWORD}" --define gpg_sign=true \
  //deploy:jazzer-junit.publish
