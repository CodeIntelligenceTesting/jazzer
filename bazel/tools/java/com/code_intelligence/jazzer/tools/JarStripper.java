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

package com.code_intelligence.jazzer.tools;

import static java.util.Collections.unmodifiableMap;
import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.mapping;
import static java.util.stream.Collectors.partitioningBy;
import static java.util.stream.Collectors.toList;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.util.AbstractMap.SimpleEntry;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.stream.IntStream;
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
      System.err.println("Usage: in.jar out.jar [[+]path]...");
      System.exit(1);
    }

    Path inFile = Paths.get(args[0]);
    Path outFile = Paths.get(args[1]);
    Map<Boolean, List<String>> rawPaths =
        unmodifiableMap(
            Arrays.stream(args)
                .skip(2)
                .map(
                    arg -> {
                      if (arg.startsWith("+")) {
                        return new SimpleEntry<>(true, arg.substring(1));
                      } else {
                        return new SimpleEntry<>(false, arg);
                      }
                    })
                .collect(partitioningBy(e -> e.getKey(), mapping(e -> e.getValue(), toList()))));

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
      PathMatcher pathsToDelete = toPathMatcher(zipFs, rawPaths.get(false), false);
      PathMatcher pathsToKeep = toPathMatcher(zipFs, rawPaths.get(true), true);
      try (Stream<Path> walk = Files.walk(zipFs.getPath(""))) {
        walk.sorted(Comparator.reverseOrder())
            .filter(
                path ->
                    (pathsToKeep != null && !pathsToKeep.matches(path))
                        || (pathsToDelete != null && pathsToDelete.matches(path)))
            .forEach(
                path -> {
                  try {
                    Files.delete(path);
                  } catch (IOException e) {
                    throw new UncheckedIOException(e);
                  }
                });
      }
    } catch (Throwable e) {
      Throwable throwable = e;
      if (throwable instanceof UncheckedIOException) {
        throwable = throwable.getCause();
      }
      throwable.printStackTrace();
      System.exit(1);
    }
  }

  private static PathMatcher toPathMatcher(FileSystem fs, List<String> paths, boolean keep) {
    if (paths.isEmpty()) {
      return null;
    }
    return fs.getPathMatcher(
        String.format(
            "glob:{%s}",
            paths.stream()
                .flatMap(pattern -> keep ? toKeepGlobs(pattern) : toRemoveGlobs(pattern))
                .collect(joining(","))));
  }

  private static Stream<String> toRemoveGlobs(String path) {
    if (path.endsWith("/**")) {
      // When removing all contents of a directory, also remove the directory itself.
      return Stream.of(path, path.substring(0, path.length() - "/**".length()));
    } else {
      return Stream.of(path);
    }
  }

  private static Stream<String> toKeepGlobs(String path) {
    // When keeping something, also keep all parents.
    String[] segments = path.split("/");
    return Stream.concat(
        Stream.of(path),
        IntStream.range(0, segments.length)
            .mapToObj(i -> Arrays.stream(segments).limit(i).collect(joining("/"))));
  }
}
