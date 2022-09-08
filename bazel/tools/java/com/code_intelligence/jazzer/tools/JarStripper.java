// Copyright 2022 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.code_intelligence.jazzer.tools;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class JarStripper {
  private static final Map<String, String> ZIP_FS_PROPERTIES = new HashMap<>();
  static {
    // We copy the input to the output path before modifying, so don't try to create a new file at
    // that path if something went wrong.
    ZIP_FS_PROPERTIES.put("create", "false");
  }

  public static void main(String[] args) {
    if (args.length < 2) {
      System.err.println(
          "Hermetically removes files and directories from .jar files by relative paths.");
      System.err.println("Usage: in.jar out.jar [relative path]...");
      System.exit(1);
    }

    Path inFile = Paths.get(args[0]);
    Path outFile = Paths.get(args[1]);
    List<String> rawPathsToDelete =
        Collections.unmodifiableList(Arrays.stream(args).skip(2).collect(Collectors.toList()));

    try {
      Files.copy(inFile, outFile);
      if (!outFile.toFile().setWritable(true)) {
        System.err.printf("Failed to make %s writable", outFile);
        System.exit(1);
      }
    } catch (IOException e) {
      e.printStackTrace();
      System.exit(1);
    }

    URI outUri = null;
    try {
      outUri = new URI("jar", outFile.toUri().toString(), null);
    } catch (URISyntaxException e) {
      e.printStackTrace();
      System.exit(1);
    }

    // Ensure that the ZipFileSystem uses a system-independent time zone for mtimes.
    // https://github.com/openjdk/jdk/blob/4d64076058a4ec5df101b06572195ed5fdee6f64/src/jdk.zipfs/share/classes/jdk/nio/zipfs/ZipUtils.java#L241
    TimeZone.setDefault(TimeZone.getTimeZone("UTC"));

    try (FileSystem zipFs = FileSystems.newFileSystem(outUri, ZIP_FS_PROPERTIES)) {
      String globPattern = String.format("glob:{%s}",
          rawPathsToDelete.stream()
              .flatMap(pattern -> {
                if (pattern.endsWith("/**")) {
                  // When removing all contents of a directory, also remove the directory itself.
                  return Stream.of(
                      pattern, pattern.substring(0, pattern.length() - "/**".length()));
                } else {
                  return Stream.of(pattern);
                }
              })
              .collect(Collectors.joining(",")));
      PathMatcher pathsToDelete = zipFs.getPathMatcher(globPattern);
      try (Stream<Path> walk = Files.walk(zipFs.getPath(""))) {
        walk.sorted(Comparator.reverseOrder()).filter(pathsToDelete::matches).forEach(path -> {
          try {
            Files.delete(path);
          } catch (IOException e) {
            throw new RuntimeException(e);
          }
        });
      }
    } catch (Throwable e) {
      Throwable throwable = e;
      if (throwable instanceof RuntimeException) {
        throwable = throwable.getCause();
      }
      throwable.printStackTrace();
      System.exit(1);
    }
  }
}
