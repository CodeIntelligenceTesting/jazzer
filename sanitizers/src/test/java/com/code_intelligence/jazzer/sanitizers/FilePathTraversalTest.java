/*
 * Copyright 2025 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.code_intelligence.jazzer.sanitizers;

import static com.code_intelligence.jazzer.sanitizers.FilePathTraversal.toAbsolutePath;
import static com.code_intelligence.jazzer.sanitizers.FilePathTraversal.toRelativePath;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class FilePathTraversalTest {

  static Stream<Arguments> pathsToRelative() {
    // CWD, target, expectedRelative, expectedAbsolute
    return Stream.of(
        arguments(
            Paths.get("/home/user1"),
            Paths.get("test/A"),
            Paths.get("test/A"),
            Paths.get("/home/user1/test/A")),
        arguments(
            Paths.get("/home/user1"), Paths.get("../A"), Paths.get("../A"), Paths.get("/home/A")),
        arguments(
            Paths.get("/"), Paths.get("/test/me"), Paths.get("test/me"), Paths.get("/test/me")),
        arguments(
            Paths.get("/home/user1"),
            Paths.get("/test/me"),
            Paths.get("../../test/me"),
            Paths.get("/test/me")),
        arguments(
            Paths.get("/home/user1"),
            Paths.get("/home/user2/A/B/C"),
            Paths.get("../user2/A/B/C"),
            Paths.get("/home/user2/A/B/C")),
        arguments(
            Paths.get("/home/user1/Data"),
            Paths.get("../A/B/C"),
            Paths.get("../A/B/C"),
            Paths.get("/home/user1/A/B/C")));
  }

  @ParameterizedTest
  @MethodSource("pathsToRelative")
  @DisabledOnOs(OS.WINDOWS)
  void toRelativeAndAbsolutePath_test(
      Path cwd, Path target, Path expectedRelative, Path expectedAbsolute) {
    Optional<Path> relative = toRelativePath(target, cwd);
    if (expectedRelative == null) {
      assertThat(relative).isEqualTo(Optional.empty());
    } else {
      assertThat(relative).isEqualTo(Optional.of(expectedRelative));
      assertThat(expectedRelative.isAbsolute()).isFalse();
    }
    assertThat(toAbsolutePath(target, cwd)).isEqualTo(Optional.of(expectedAbsolute));
    assertThat(expectedAbsolute.isAbsolute()).isTrue();
  }

  static Stream<Arguments> pathsToRelativeWin() {
    // CWD, target, expectedRelative, expectedAbsolute
    return Stream.of(
        arguments(
            Paths.get("C:\\home\\user1"),
            Paths.get("test\\A"),
            Paths.get("test\\A"),
            Paths.get("C:\\home\\user1\\test\\A")),
        arguments(
            Paths.get("C:\\home\\user1"),
            Paths.get("..\\A"),
            Paths.get("..\\A"),
            Paths.get("C:\\home\\A")),
        arguments(
            Paths.get("C:\\"),
            Paths.get("C:\\test\\me"),
            Paths.get("test\\me"),
            Paths.get("C:\\test\\me")),
        arguments(
            Paths.get("C:\\home\\user1"),
            Paths.get("C:\\test\\me"),
            Paths.get("..\\..\\test\\me"),
            Paths.get("C:\\test\\me")),
        arguments(
            Paths.get("C:\\home\\user1"),
            Paths.get("C:\\home\\user2\\A\\B\\C"),
            Paths.get("..\\user2\\A\\B\\C"),
            Paths.get("C:\\home\\user2\\A\\B\\C")),
        arguments(
            Paths.get("C:\\home\\user1\\Data"),
            Paths.get("..\\A\\B\\C"),
            Paths.get("..\\A\\B\\C"),
            Paths.get("C:\\home\\user1\\A\\B\\C")),
        arguments(
            Paths.get("C:\\home\\user1"),
            Paths.get("D:\\A\\B\\C"),
            null, // there is no relative path from CWD to D drive
            Paths.get("D:\\A\\B\\C")));
  }

  @ParameterizedTest
  @MethodSource("pathsToRelativeWin")
  @EnabledOnOs(OS.WINDOWS)
  void toRelativePath_test_windows(
      Path cwd, Path target, Path expectedRelative, Path expectedAbsolute) {

    Optional<Path> relative = toRelativePath(target, cwd);
    if (expectedRelative == null) {
      assertThat(relative).isEqualTo(Optional.empty());
    } else {
      assertThat(relative).isEqualTo(Optional.of(expectedRelative));
      assertThat(expectedRelative.isAbsolute()).isFalse();
    }
    assertThat(toAbsolutePath(target, cwd)).isEqualTo(Optional.of(expectedAbsolute));
    assertThat(expectedAbsolute.isAbsolute()).isTrue();
  }
}
