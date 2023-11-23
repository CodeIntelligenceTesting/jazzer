#!/usr/bin/env bash
#
# Copyright 2024 Code Intelligence GmbH
#
# By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
#
# The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
# located in the root directory of the project.
#

set -eu

fail() {
  echo "$1"
  exit 1
}

cd "$BUILD_WORKSPACE_DIRECTORY" || fail "BUILD_WORKSPACE_DIRECTORY not found"

JAZZER_COORDINATES=$1
[[ "$JAZZER_COORDINATES" != *-dev ]] || fail "--//deploy:jazzer_version must be set to a release version, got: $JAZZER_COORDINATES"

[ -z "${MAVEN_USER+x}" ] && \
  fail "Set MAVEN_USER to the repository user"
[ -z "${MAVEN_PASSWORD+x}" ] && \
  fail "Set MAVEN_PASSWORD to the repository password"
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

MAVEN_REPO=https://gitlab.code-intelligence.com/api/v4/projects/89/packages/maven

# The Jazzer jar itself bundles native libraries for multiple architectures and thus can't be built
# on the local machine. It is obtained from CI and passed in via JAZZER_JAR_PATH.
bazel build //deploy:jazzer-docs //deploy:jazzer-sources //deploy:jazzer-pom

JAZZER_DOCS_PATH=$PWD/$(bazel cquery --output=files //deploy:jazzer-docs)
JAZZER_POM_PATH=$PWD/$(bazel cquery --output=files //deploy:jazzer-pom)

bazel run --define "maven_repo=${MAVEN_REPO}" --define "maven_user=${MAVEN_USER}" \
  --define "maven_password=${MAVEN_PASSWORD}" \
  //deploy:jazzer-api.publish
MAVEN_REPO="$MAVEN_REPO" MAVEN_USER="$MAVEN_USER" MAVEN_PASSWORD="$MAVEN_PASSWORD" \
  bazel run @rules_jvm_external//private/tools/java/com/github/bazelbuild/rules_jvm_external/maven:MavenPublisher -- \
  "$JAZZER_COORDINATES" "$JAZZER_POM_PATH" "$JAZZER_JAR_PATH" "javadoc=${JAZZER_DOCS_PATH}"
bazel run --define "maven_repo=${MAVEN_REPO}" --define "maven_user=${MAVEN_USER}" \
  --define "maven_password=${MAVEN_PASSWORD}" \
  //deploy:jazzer-junit.publish
