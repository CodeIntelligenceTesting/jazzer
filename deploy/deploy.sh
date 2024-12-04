#!/usr/bin/env bash
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

set -eu

fail() {
  echo "$1"
  exit 1
}

cd "$BUILD_WORKSPACE_DIRECTORY" || fail "BUILD_WORKSPACE_DIRECTORY not found"

JAZZER_COORDINATES=$1
[[ "$JAZZER_COORDINATES" != *-dev ]] || fail "--//deploy:jazzer_version must be set to a release version, got: $JAZZER_COORDINATES"

echo "$RELEASE_SIGNING_KEY_PRIVATE" | gpg --import
echo "default-key $RELEASE_SIGNING_KEY_ID" > $HOME/.gnupg/gpg.conf

[ -z "${MAVEN_USER+x}" ] && \
  fail "Set MAVEN_USER to the Sonatype OSSRH user"
[ -z "${MAVEN_PASSWORD+x}" ] && \
  fail "Set MAVEN_PASSWORD to the Sonatype OSSRH password"
[ -z "${JAZZER_JAR_PATH+x}" ] && \
  fail "Set JAZZER_JAR_PATH to the absolute path of jazzer.jar obtained from the release GitHub Actions workflow"
[ ! -f "${JAZZER_JAR_PATH}" ] && \
  fail "JAZZER_JAR_PATH does not exist at '$JAZZER_JAR_PATH'"

# --- begin runfiles.bash initialization v3 ---
# Copy-pasted from the Bazel Bash runfiles library v3.
set -uo pipefail; set +e; f=bazel_tools/tools/bash/runfiles/runfiles.bash
source "${RUNFILES_DIR:-/dev/null}/$f" 2>/dev/null || \
  source "$(grep -sm1 "^$f " "${RUNFILES_MANIFEST_FILE:-/dev/null}" | cut -f2- -d' ')" 2>/dev/null || \
  source "$0.runfiles/$f" 2>/dev/null || \
  source "$(grep -sm1 "^$f " "$0.runfiles_manifest" | cut -f2- -d' ')" 2>/dev/null || \
  source "$(grep -sm1 "^$f " "$0.exe.runfiles_manifest" | cut -f2- -d' ')" 2>/dev/null || \
  { echo>&2 "ERROR: cannot find $f"; exit 1; }; f=; set -e
# --- end runfiles.bash initialization v3 ---

# JAZZER_EXECPATH is a path of the form "external/remotejdk_17/bin/java". We need to strip of the
# leading external to get a path we can pass to rlocation.
java_rlocationpath=$(echo "$JAVA_EXECPATH" | cut -d/ -f2-)
java=$(rlocation "$java_rlocationpath")
"$java" -jar "${JAZZER_JAR_PATH}" --version 2>&1 | grep '^Jazzer v' || \
  fail "JAZZER_JAR_PATH is not a valid jazzer.jar"

MAVEN_REPO=https://oss.sonatype.org/service/local/staging/deploy/maven2

# The Jazzer jar itself bundles native libraries for multiple architectures and thus can't be built
# on the local machine. It is obtained from CI and passed in via JAZZER_JAR_PATH.
bazel build //deploy:jazzer-docs //deploy:jazzer-sources //deploy:jazzer-pom

JAZZER_DOCS_PATH=$PWD/$(bazel cquery --output=files //deploy:jazzer-docs)
JAZZER_SOURCES_PATH=$PWD/$(bazel cquery --output=files //deploy:jazzer-sources)
JAZZER_POM_PATH=$PWD/$(bazel cquery --output=files //deploy:jazzer-pom)

bazel run --define "maven_repo=${MAVEN_REPO}" --define "maven_user=${MAVEN_USER}" \
  --define "maven_password=${MAVEN_PASSWORD}" --define gpg_sign=true \
  //deploy:jazzer-api.publish
MAVEN_REPO="$MAVEN_REPO" GPG_SIGN="true" MAVEN_USER="$MAVEN_USER" MAVEN_PASSWORD="$MAVEN_PASSWORD" \
  bazel run @rules_jvm_external//private/tools/java/com/github/bazelbuild/rules_jvm_external/maven:MavenPublisher -- \
  "$JAZZER_COORDINATES" "$JAZZER_POM_PATH" "$JAZZER_JAR_PATH" "sources=${JAZZER_SOURCES_PATH},javadoc=${JAZZER_DOCS_PATH}"
bazel run --define "maven_repo=${MAVEN_REPO}" --define "maven_user=${MAVEN_USER}" \
  --define "maven_password=${MAVEN_PASSWORD}" --define gpg_sign=true \
  //deploy:jazzer-junit.publish
