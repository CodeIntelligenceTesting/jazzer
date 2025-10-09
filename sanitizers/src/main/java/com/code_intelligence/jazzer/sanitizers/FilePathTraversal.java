/*
 * Copyright 2025 Code Intelligence GmbH
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
package com.code_intelligence.jazzer.sanitizers;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.MethodHook;
import java.io.File;
import java.lang.invoke.MethodHandle;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;
import java.util.function.Supplier;

/**
 * This tests for a file read or write of a specific file path whether relative or absolute.
 *
 * <p>This checks only for literal, absolute, normalized paths. It does not process symbolic links.
 *
 * <p>The default target is "../jazzer-traversal"."
 *
 * <p>Users may customize the target using the BugDetectors API, e.g. by {@code
 * BugDetectors.setFilePathTraversalTarget(() -> Path.of("..", "jazzer-traversal"))}.
 *
 * <p>TODO: This sanitizer does not currently check for reading metadata from the target file.
 */
public class FilePathTraversal {
  public static final Path DEFAULT_TARGET = Paths.get("..", "jazzer-traversal");

  // Set via reflection by Jazzer's BugDetectors API.
  public static final AtomicReference<Supplier<Path>> target =
      new AtomicReference<>(() -> DEFAULT_TARGET);
  public static final AtomicReference<Predicate<Path>> checkPath =
      new AtomicReference<>((Path ignored) -> true);

  // When guiding the fuzzer towards the target path, sometimes both the absolute and relative paths
  // are valid. In this case, we toggle between them randomly.
  // The random part is important because it is possible to set several targets in a fuzz test with
  // try(target1...){
  //    ...
  //    try(target2...) {
  //       ...
  // If we toggle in fix pattern, the fuzzer might guide towards the same blocks towards the same
  // target.
  // Randomizing the toggle counter sidesteps this issue.
  private static final int MAX_TARGET_FOCUS_COUNT = 23;
  private static boolean guideTowardsAbsoluteTargetPath = true;
  private static int toggleCounter = 1;

  public static Optional<Path> toAbsolutePath(Path path, Path currentDir) {
    try {
      if (path.isAbsolute()) {
        return Optional.of(path.normalize());
      }
      return Optional.of(currentDir.resolve(path).normalize());
    } catch (InvalidPathException e) {
      return Optional.empty();
    }
  }

  public static Optional<Path> toRelativePath(Path path, Path currentDir) {
    try {
      if (path.isAbsolute()) {
        return Optional.of(currentDir.relativize(path).normalize());
      }
      return Optional.of(path.normalize());
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
  }

  // intentionally skipping createLink and createSymbolicLink
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "createDirectory")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "createDirectories")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "createFile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "createTempDirectory")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "createTempFile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "delete")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "deleteIfExists")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "lines")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "newByteChannel")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "newBufferedReader")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "newBufferedWriter")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "readString")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "readAllBytes")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "readAllLines")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "readSymbolicLink")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "write")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "writeString")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "newInputStream")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "newOutputStream")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "probeContentType")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.channels.FileChannel",
      targetMethod = "open")
  public static void pathFirstArgHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    if (arguments.length > 0) {
      detectAndGuidePathTraversal(arguments[0], hookId);
    }
  }

  /** Checks to confirm that a path that is read from or written to is in an allowed directory. */
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "copy")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "mismatch")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.file.Files",
      targetMethod = "move")
  public static void copyMismatchMvHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    if (arguments.length > 1) {
      detectAndGuidePathTraversal(arguments[0], hookId);
      detectAndGuidePathTraversal(arguments[1], hookId);
    }
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.io.FileReader",
      targetMethod = "<init>")
  public static void fileReaderHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    if (arguments.length > 0) {
      detectAndGuidePathTraversal(arguments[0], hookId);
    }
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.io.FileWriter",
      targetMethod = "<init>")
  public static void fileWriterHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    if (arguments.length > 0) {
      detectAndGuidePathTraversal(arguments[0], hookId);
    }
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.io.FileInputStream",
      targetMethod = "<init>")
  public static void fileInputStreamHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    if (arguments.length > 0) {
      detectAndGuidePathTraversal(arguments[0], hookId);
    }
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.io.FileOutputStream",
      targetMethod = "<init>")
  public static void processFileOutputStartHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    if (arguments.length > 0) {
      detectAndGuidePathTraversal(arguments[0], hookId);
    }
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.util.Scanner",
      targetMethod = "<init>")
  public static void scannerHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    if (arguments.length > 0) {
      detectAndGuidePathTraversal(arguments[0], hookId);
    }
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.io.FileOutputStream",
      targetMethod = "<init>")
  public static void fileOutputStreamHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    if (arguments.length > 0) {
      detectAndGuidePathTraversal(arguments[0], hookId);
    }
  }

  private static void detectAndGuidePathTraversal(Object obj, int hookId) {
    if (obj == null) {
      return;
    }

    Path targetPath = target.get().get();

    String query;
    if (obj instanceof Path) {
      query = ((Path) obj).normalize().toString();
    } else if (obj instanceof File) {
      try {
        query = ((File) obj).toPath().normalize().toString();
      } catch (InvalidPathException e) {
        return;
      }
    } else if (obj instanceof String) {
      try {
        query = (String) obj;
      } catch (InvalidPathException e) {
        return;
      }
    } else { // not a path, file or string
      return;
    }

    Predicate<Path> checkAllowed = checkPath.get();
    boolean isPathAllowed = checkAllowed == null || checkAllowed.test(Paths.get(query).normalize());
    if (!isPathAllowed) {
      Jazzer.reportFindingFromHook(
          new FuzzerSecurityIssueCritical(
              "File path traversal: "
                  + query
                  + "\n   Path is not allowed by the user-defined predicate."
                  + "\n   Current path traversal fuzzing target: "
                  + targetPath));
    }

    // Users can set the atomic function to return null to disable the fuzzer guidance.
    if (targetPath == null) {
      return;
    }
    targetPath = targetPath.normalize();

    Path currentDir = Paths.get("").toAbsolutePath();
    Path absTarget = toAbsolutePath(targetPath, currentDir).orElse(null);
    Path relTarget = toRelativePath(targetPath, currentDir).orElse(null);
    if (absTarget == null && relTarget == null) {
      return;
    }

    if ((absTarget != null && absTarget.toString().equals(query))
        || (relTarget != null && relTarget.toString().equals(query))) {
      Jazzer.reportFindingFromHook(
          new FuzzerSecurityIssueCritical(
              "File path traversal: "
                  + query
                  + "\n   Reached current path traversal fuzzing target: "
                  + targetPath));
    }

    if (absTarget != null && relTarget != null) {
      if (guideTowardsAbsoluteTargetPath) {
        Jazzer.guideTowardsContainment(query, absTarget.toString(), hookId);
      } else {
        Jazzer.guideTowardsContainment(query, relTarget.toString(), hookId);
      }
      if (--toggleCounter <= 0) {
        guideTowardsAbsoluteTargetPath = !guideTowardsAbsoluteTargetPath;
        toggleCounter = ThreadLocalRandom.current().nextInt(1, MAX_TARGET_FOCUS_COUNT + 1);
      }
    } else {
      Jazzer.guideTowardsContainment(
          query, (absTarget != null ? absTarget : relTarget).toString(), hookId);
    }
  }
}
