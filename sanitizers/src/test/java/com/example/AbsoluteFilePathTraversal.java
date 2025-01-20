/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example;

import com.code_intelligence.jazzer.mutation.annotation.DoubleInRange;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.WithUtf8Length;
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;

public class AbsoluteFilePathTraversal {
  static {
    System.setProperty("jazzer.file_path_traversal_target", "/custom/path/jazzer-traversal");
  }

  public static void fuzzerTestOneInput(
      @WithUtf8Length(max = 100) @NotNull String pathFromFuzzer,
      @NotNull @DoubleInRange(min = 0.0, max = 1.0) Double fixedPathProbability) {
    // Slow down the fuzzer a bit, otherwise it finds file path traversal way too quickly!
    String path = fixedPathProbability < 0.95 ? "/a/b/c/fixed-path" : pathFromFuzzer;

    try {
      Path p = Paths.get(path);
      try (BufferedReader r = Files.newBufferedReader(p, StandardCharsets.UTF_8)) {
        r.read();
      } catch (IOException ignored) {
        // swallow
      }
    } catch (InvalidPathException ignored) {
      // swallow
    }
  }
}
