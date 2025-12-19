/*
 * Copyright 2026 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.mutation.support;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;

public class GlobTestSupport {
  private static final boolean ON_WINDOWS = FileSystems.getDefault().getSeparator().equals("\\");

  public static void mockSourceDirectory(Path base) throws IOException {
    // if base exists and has files, assume already populated
    if (Files.exists(base) && Files.list(base).findAny().isPresent()) {
      return;
    }
    makeFiles(
        base,
        // top level
        "a.txt",
        "b.zip",
        "c.zip.txt",
        // subdirectories
        "sub/b.txt",
        "sub/b.json",
        "sub/b.xml",
        "sub/c.zip",
        "sub/deep/c.txt",
        "sub/deep/c.json",
        "sub/deep/c.xml",
        "sub/deep/corpus/d.xml",
        "sub/deep/corpus/d.txt",
        "sub/deeper/than/mah.txt",
        "sub/deeper/than/foo.json",
        "sub/deeper/than/bar.xml",
        "test/c/d/foo.json",
        "test/c/d/bar.txt",
        "alpha-numeric/1a.numeric",
        "alpha-numeric/5h.numeric",
        "alpha-numeric/6I.numeric",
        "alpha-numeric/9Z.numeric",
        "escaped/[/test.escaped",
        // files with special glob characters
        // * and ? are not allowed on Windows
        "weird/{}{braces}.glob",
        "weird/[]{}.glob");

    if (!ON_WINDOWS) {
      // * and ? are not allowed in filenames on Windows
      makeFiles(
          base,
          "no-windows/asdf[sdf*df]f.glob",
          "no-windows/hey?ho.glob",
          "no-windows/stars****stars.glob",
          "no-windows/*?hello[there]{}.glob",
          "no-windows/backslash\\\\-es.glob",
          // \\ is a directory separator on Windows
          "no-windows/file\\ with backslash.glob");

      // On Windows, we cannot make files or directories unreadable in a way that the JVM respects.
      // Make an unreadable directory to ensure it's skipped without error
      Path unreadableDir = base.resolve("unreadable");
      Files.createDirectory(unreadableDir);
      unreadableDir.toFile().setReadable(false);
      unreadableDir.toFile().setExecutable(false);

      // Make an unreadable file to ensure it's skipped without error
      Path unreadableFile = base.resolve("unreadable_file.txt");
      writeUtf8(unreadableFile, "unreadable_file.txt");
      unreadableFile.toFile().setReadable(false);
      unreadableFile.toFile().setWritable(false);
      unreadableFile.toFile().setExecutable(false);
    }
  }

  private static void makeFiles(Path base, String... paths) throws IOException {
    for (String path : paths) {
      Path file = base.resolve(path);
      Files.createDirectories(file.getParent());
      writeUtf8(file, path);
    }
  }

  private static void writeUtf8(Path path, String content) throws IOException {
    Files.write(path, content.getBytes(StandardCharsets.UTF_8));
  }
}
