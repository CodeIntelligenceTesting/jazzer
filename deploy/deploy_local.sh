#!/usr/bin/env bash
#
# Copyright 2024 Code Intelligence GmbH
#
# By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
#
# The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
# located in the root directory of the project.
#

cd "$BUILD_WORKSPACE_DIRECTORY" || fail "BUILD_WORKSPACE_DIRECTORY not found"

bazel run --define "maven_repo=file://$HOME/.m2/repository"  //deploy:jazzer.publish
bazel run --define "maven_repo=file://$HOME/.m2/repository"  //deploy:jazzer-junit.publish
bazel run --define "maven_repo=file://$HOME/.m2/repository"  //deploy:jazzer-api.publish
