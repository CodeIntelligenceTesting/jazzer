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

import static java.util.Collections.EMPTY_LIST;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class GlobUtils {
  protected static List<Path> collectPathsForGlob(Path baseDir, String glob) {
    if (ON_WINDOWS) {
      glob = glob.replace("\\\\", "/");
    }
    int firstGlobChar = indexOfFirstGlobChar(glob);
    if (firstGlobChar == -1) {
      Path target = baseDir.resolve(unescapeGlobChars(glob)).toAbsolutePath().normalize();
      return Files.isRegularFile(target) ? Arrays.asList(target) : EMPTY_LIST;
    }

    String prefix = glob.substring(0, firstGlobChar);
    int lastSeparator =
        ON_WINDOWS
            ? Math.max(prefix.lastIndexOf('/'), prefix.lastIndexOf("\\\\"))
            : prefix.lastIndexOf('/');

    // The 'start' path is always absolute
    Path start;
    String remainingPattern;
    if (lastSeparator == -1) {
      start = baseDir.toAbsolutePath().normalize();
      remainingPattern = glob;
    } else {
      String basePrefix = prefix.substring(0, lastSeparator);
      start = baseDir.resolve(unescapeGlobChars(basePrefix)).toAbsolutePath().normalize();
      remainingPattern = glob.substring(lastSeparator + 1);
    }
    if (!Files.exists(start)) {
      return EMPTY_LIST;
    }

    // The matcher is always relative to start path
    PathMatcher matcher = FileSystems.getDefault().getPathMatcher("glob:" + remainingPattern);

    List<Path> matches = new ArrayList<>();
    try {
      Files.walkFileTree(
          start,
          new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
              if (!Files.isRegularFile(file)) {
                return FileVisitResult.CONTINUE;
              }
              Path relativePath = start.relativize(file);
              if (matcher.matches(relativePath)) {
                matches.add(file);
              }
              return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
              return FileVisitResult.CONTINUE;
            }
          });
    } catch (IOException ignored) {
      // Best effort - return what we found so far
    }
    return matches;
  }

  private static final String SPECIAL_CHARS = "*{}[]-?\\";

  private static boolean isSpecialChar(char c) {
    return SPECIAL_CHARS.indexOf(c) != -1;
  }

  protected static Path unescapeGlobChars(String glob) {
    StringBuilder sb = new StringBuilder();
    char[] chars = glob.toCharArray();
    boolean escaped = false;

    for (char c : chars) {
      if (escaped) {
        if (!isSpecialChar(c)) {
          sb.append('\\');
        }
        sb.append(c);
        escaped = false;
      } else if (c == '\\') {
        escaped = true;
      } else {
        sb.append(c);
      }
    }

    return Paths.get(sb.toString());
  }

  private static final String GLOB_CHARS = "*?[{";

  private static boolean isGlobChar(char c) {
    return GLOB_CHARS.indexOf(c) != -1;
  }

  protected static final boolean ON_WINDOWS = FileSystems.getDefault().getSeparator().equals("\\");

  private static int indexOfFirstGlobChar(String glob) {
    char[] chars = glob.toCharArray();
    boolean escaped = false;
    for (int i = 0; i < chars.length; i++) {
      char c = chars[i];
      if (escaped) {
        escaped = false;
        continue;
      } else if (c == '\\') {
        escaped = true;
      }
      if (isGlobChar(c)) {
        return i;
      }
    }
    return -1;
  }
}
