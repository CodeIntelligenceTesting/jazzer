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
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This tests for a file read or write of a specific file path whether relative or absolute.
 *
 * <p>This checks only for literal, absolute, normalized paths. It does not process symbolic links.
 *
 * <p>The default target is {@link FilePathTraversal#DEFAULT_TARGET_STRING}
 *
 * <p>Users may customize a customize the target by setting the full path in the environment
 * variable {@link FilePathTraversal#FILE_PATH_TARGET_KEY}
 *
 * <p>This does not currently check for reading metadata from the target file.
 */
public class FilePathTraversal {
  public static final String FILE_PATH_TARGET_KEY = "jazzer.file_path_traversal_target";
  public static final String DEFAULT_TARGET_STRING = "../jazzer-traversal";

  private static final Logger LOG = Logger.getLogger(FilePathTraversal.class.getName());

  private static Path RELATIVE_TARGET;
  private static Path ABSOLUTE_TARGET;
  private static boolean IS_DISABLED = false;
  private static boolean IS_SET_UP = false;

  private static void setUp() {
    String customTarget = System.getProperty(FILE_PATH_TARGET_KEY);
    if (customTarget != null && !customTarget.isEmpty()) {
      LOG.log(Level.FINE, "custom target loaded: " + customTarget);
      setTargets(customTarget);
    } else {
      // check that this isn't being run at the root directory
      Path cwd = Paths.get(".").toAbsolutePath();
      if (cwd.getParent() == null) {
        LOG.warning(
            "Can't run from the root directory with the default target. "
                + "The FilePathTraversal sanitizer is disabled.");
        IS_DISABLED = true;
      }
      setTargets(DEFAULT_TARGET_STRING);
    }
  }

  private static void setTargets(String targetPath) {
    Path p = Paths.get(targetPath);
    Path pwd = Paths.get(".");
    if (p.isAbsolute()) {
      ABSOLUTE_TARGET = p.toAbsolutePath().normalize();
      RELATIVE_TARGET = pwd.toAbsolutePath().relativize(ABSOLUTE_TARGET).normalize();
    } else {
      ABSOLUTE_TARGET = pwd.resolve(p).toAbsolutePath().normalize();
      RELATIVE_TARGET = p.normalize();
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
      targetMethod = "newBufferedReader")
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
      targetClassName = "java.nio.file.probeContentType",
      targetMethod = "open")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.channels.FileChannel",
      targetMethod = "open")
  public static void pathFirstArgHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    if (arguments.length > 0) {
      Object argObj = arguments[0];
      if (argObj instanceof Path) {
        checkPath((Path) argObj, hookId);
      }
    }
  }

  /**
   * Checks to confirm that a path that is read from or written to is in an allowed directory.
   *
   * @param method
   * @param thisObject
   * @param arguments
   * @param hookId
   */
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
      Object from = arguments[0];
      if (from instanceof Path) {
        checkPath((Path) from, hookId);
      }
      Object to = arguments[1];
      if (to instanceof Path) {
        checkPath((Path) to, hookId);
      }
    }
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.io.FileReader",
      targetMethod = "<init>")
  public static void fileReaderHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    if (arguments.length > 0) {
      checkObj(arguments[0], hookId);
    }
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.io.FileWriter",
      targetMethod = "<init>")
  public static void fileWriterHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    if (arguments.length > 0) {
      checkObj(arguments[0], hookId);
    }
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.io.FileInputStream",
      targetMethod = "<init>")
  public static void fileInputStreamHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    if (arguments.length > 0) {
      checkObj(arguments[0], hookId);
    }
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.io.FileOutputStream",
      targetMethod = "<init>")
  public static void processFileOutputStartHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    if (arguments.length > 0) {
      checkObj(arguments[0], hookId);
    }
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.util.Scanner",
      targetMethod = "<init>")
  public static void scannerHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    if (arguments.length > 0) {
      checkObj(arguments[0], hookId);
    }
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.io.FileOutputStream",
      targetMethod = "<init>")
  public static void fileOutputStreamHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    if (arguments.length > 0) {
      checkObj(arguments[0], hookId);
    }
  }

  private static void checkObj(Object obj, int hookId) {
    if (obj instanceof String) {
      checkString((String) obj, hookId);
    } else if (obj instanceof Path) {
      checkPath((Path) obj, hookId);
    } else if (obj instanceof File) {
      checkFile((File) obj, hookId);
    }
  }

  private static void checkPath(Path p, int hookId) {
    check(p);
    Path normalized = p.normalize();
    if (p.isAbsolute()) {
      Jazzer.guideTowardsEquality(normalized.toString(), ABSOLUTE_TARGET.toString(), hookId);
    } else {
      Jazzer.guideTowardsEquality(normalized.toString(), RELATIVE_TARGET.toString(), hookId);
    }
  }

  private static void checkFile(File f, int hookId) {
    try {
      check(f.toPath());
    } catch (InvalidPathException e) {
      // TODO: give up -- for now
      return;
    }
    Path normalized = f.toPath().normalize();
    if (normalized.isAbsolute()) {
      Jazzer.guideTowardsEquality(normalized.toString(), ABSOLUTE_TARGET.toString(), hookId);
    } else {
      Jazzer.guideTowardsEquality(normalized.toString(), RELATIVE_TARGET.toString(), hookId);
    }
  }

  private static void checkString(String s, int hookId) {
    try {
      check(Paths.get(s));
    } catch (InvalidPathException e) {
      checkFile(new File(s), hookId);
      // TODO -- give up for now
      return;
    }
    Path normalized = Paths.get(s);
    if (normalized.isAbsolute()) {
      Jazzer.guideTowardsEquality(s, ABSOLUTE_TARGET.toString(), hookId);
    } else {
      Jazzer.guideTowardsEquality(s, RELATIVE_TARGET.toString(), hookId);
    }
  }

  private static void check(Path p) {
    // super lazy initialization -- race condition with unit test if this is set in a static block
    synchronized (LOG) {
      if (!IS_SET_UP) {
        setUp();
        IS_SET_UP = true;
      }
    }
    if (IS_DISABLED) {
      return;
    }

    if (p.toAbsolutePath().normalize().equals(ABSOLUTE_TARGET)) {
      Jazzer.reportFindingFromHook(new FuzzerSecurityIssueCritical("File path traversal: " + p));
    }
  }
}
