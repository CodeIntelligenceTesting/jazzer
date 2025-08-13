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

public class FilePathTraversalPass {
  @BeforeEach
  public void setUp() {
    setTarget(Paths.get("..", "..", "hello"));
  }

  @FuzzTest
  void beforeEachWorks(boolean ignore) {
    tryPathTraversal("test");
  }

  @FuzzTest
  void overwritingBeforeEachWorks(boolean ignore) {
    try (SilentCloseable ignore1 = setTarget(Paths.get("..", "..", "jazzer-hey"))) {
      tryPathTraversal("..", "..", "hello");
    }
  }

  @FuzzTest
  void allow(boolean ignore) {
    try (SilentCloseable ignore1 =
        BugDetectors.setFilePathTraversalAllowPath((Path p) -> p.toString().contains("secret"))) {
      tryPathTraversal("my-secret-file");
    }
  }

  @FuzzTest
  void targetMissed(boolean ignore) {
    try (SilentCloseable ignore1 =
        BugDetectors.setFilePathTraversalAllowPath((Path ignoredAgain) -> true)) {
      tryPathTraversal("some-path");
    }
  }

  @FuzzTest
  void onion(boolean ignore) {
    final Path jazzerHello = Paths.get("..", "..", "hello");
    final Path jazzerTest = Paths.get("test");
    final Path jazzerHey = Paths.get("..", "..", "jazzer-hey");
    final Path jazzerHey1 = Paths.get("..", "..", "jazzer-hey1");

    try (SilentCloseable ignored = setTarget(jazzerHey)) {
      tryPathTraversal(jazzerHello);
      try (SilentCloseable ignored1 = setTarget(jazzerTest)) {
        tryPathTraversal(jazzerHey);
        try (SilentCloseable ignored2 = setTarget(jazzerHey1)) {
          tryPathTraversal(jazzerTest);
        }
        tryPathTraversal(jazzerHey);
        tryPathTraversal(jazzerHey1);
      }
      tryPathTraversal(jazzerTest);
      tryPathTraversal(jazzerHey1);
      tryPathTraversal(jazzerHello);
    }
  }

  private static SilentCloseable setTarget(String first, String... rest) {
    return setTarget(Paths.get(first, rest));
  }

  private static SilentCloseable setTarget(Path p) {
    return BugDetectors.setFilePathTraversalTarget(() -> p);
  }

  private static void tryPathTraversal(String first, String... rest) {
    Path path = Paths.get(first, rest);
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
