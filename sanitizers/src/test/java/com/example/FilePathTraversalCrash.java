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

package com.example;

import com.code_intelligence.jazzer.api.BugDetectors;
import com.code_intelligence.jazzer.api.SilentCloseable;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.BeforeEach;

public class FilePathTraversalCrash {
  @BeforeEach
  public void setUp() {
    BugDetectors.setFilePathTraversalTarget(() -> Paths.get("..", "..", "hello"));
  }

  @FuzzTest
  void beforeEachWorks(boolean ignore) throws Exception {
    tryPathTraversal("..", "..", "hello");
  }

  @FuzzTest
  void overwritingBeforeEachWorks(boolean ignore) {
    try (SilentCloseable unused = setTarget("..", "..", "jazzer-hey")) {
      tryPathTraversal("..", "..", "jazzer-hey");
    }
  }

  @FuzzTest
  void crashWhenAllowIsFalse(boolean ignore) {
    try (SilentCloseable unused = BugDetectors.setFilePathTraversalAllowPath((Path p) -> false)) {
      tryPathTraversal("any-path-is-bad");
    }
  }

  @FuzzTest
  void crashWhenDefaultTarget(boolean ignore) {
    try (SilentCloseable unused = BugDetectors.setFilePathTraversalAllowPath((Path p) -> true)) {
      tryPathTraversal("..", "..", "hello");
    }
  }

  @FuzzTest
  void onionTarget(boolean ignore) {
    try (SilentCloseable unused = setTarget("..", "..", "jazzer-hey")) {
      try (SilentCloseable unused1 = setTarget("..", "..", "jazzer-hey1")) {
        try (SilentCloseable unused2 = setTarget("..", "..", "jazzer-hey2")) {
          tryPathTraversal("..", "..", "jazzer-hey2");
        }
      }
    }
  }

  @FuzzTest
  void cascadedTarget(boolean ignore) {
    try (SilentCloseable ignore1 = setTarget("..", "..", "jazzer-hey")) {
      // ignore
    }
    try (SilentCloseable ignore2 = setTarget("..", "..", "jazzer-hey1")) {
      // ignore
    }
    try (SilentCloseable ignore3 = setTarget("..", "..", "jazzer-hey2")) {
      tryPathTraversal("..", "..", "jazzer-hey2");
    }
  }

  @FuzzTest
  void absoluteToRelative(boolean ignore) {
    final Path cwd = Paths.get("").toAbsolutePath();
    final Path target = Paths.get("test", "A");
    // set absolute target
    try (SilentCloseable ignore1 = setTarget(cwd.resolve(target))) {
      // try to read relative path
      tryPathTraversal(target);
    }
  }

  @FuzzTest
  void relativeToAbsolute(boolean ignore) {
    final Path cwd = Paths.get("").toAbsolutePath();
    final Path target = Paths.get("test", "A");
    // set relative target
    try (SilentCloseable ignore1 = setTarget(target)) {
      // try to read absolute path
      tryPathTraversal(cwd.resolve(target));
    }
  }

  private static SilentCloseable setTarget(String first, String... rest) {
    return setTarget(Paths.get(first, rest));
  }

  private static SilentCloseable setTarget(Path p) {
    return BugDetectors.setFilePathTraversalTarget(() -> p);
  }

  private static void tryPathTraversal(String part1, String... rest) {
    Path path = Paths.get(part1, rest);
    try (FileInputStream fis = new FileInputStream(path.toString())) {
      fis.read();
    } catch (NullPointerException | IOException ignored) {
    }
  }

  private static void tryPathTraversal(Path path) {
    try (FileInputStream fis = new FileInputStream(path.toString())) {
      fis.read();
    } catch (NullPointerException | IOException ignored) {
    }
  }
}
