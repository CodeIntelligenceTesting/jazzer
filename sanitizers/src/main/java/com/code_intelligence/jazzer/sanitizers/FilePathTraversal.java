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
package com.code_intelligence.jazzer.sanitizers;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.MethodHook;

import java.io.IOException;
import java.io.File;
import java.lang.invoke.MethodHandle;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * This tests for a file read or write of a specific file name AND
 * whether that file is in an allowed directory or a descendant.
 * <p>
 * This checks only for literal, absolute, normalized paths. It does not process symbolic links.
 * <p>
 * This sanitizer will only trigger if {@link FilePathTraversal#ALLOWED_DIRS_KEY} is
 * set as an environment variable. If that is not set, this sanitizer is a no-op.
 * <p>
 * This does not check for reading metadata from files outside of the allowed directories.
 */
public class FilePathTraversal {
    public static final String FILE_NAME_ENV_KEY = "JAZZER_FILE_SYSTEM_TRAVERSAL_FILE_NAME";
    public static final String ALLOWED_DIRS_KEY = "jazzer.fs_allowed_dirs";
    public static final String DEFAULT_SENTINEL = "jazzer-traversal";
    public static final String SENTINEL =
            (System.getenv(FILE_NAME_ENV_KEY) == null ||
                    System.getenv(FILE_NAME_ENV_KEY).trim().length() == 0) ?
                    DEFAULT_SENTINEL : System.getenv(FILE_NAME_ENV_KEY);

    //intentionally skipping createLink and createSymbolicLink

    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "createDirectory"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "createDirectories"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "createFile"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "createTempDirectory"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "createTempFile"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "delete"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "deleteIfExists"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "lines"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "newByteChannel"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "newBufferedReader"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "newBufferedWriter"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "readString"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "newBufferedReader"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "readAllBytes"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "readAllLines"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "readSymbolicLink"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "write"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "writeString"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "newInputStream"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "newOutputStream"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.probeContentType",
            targetMethod = "open"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.channels.FileChannel",
            targetMethod = "open"
    )
    public static void pathFirstArgHook(
            MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
        if (arguments.length > 0) {
            Object argObj = arguments[0];
            if (argObj instanceof Path) {
                checkPath((Path)argObj);
            }
        }
    }

    /**
     * Checks to confirm that a path that is read from or written to
     * is in an allowed directory.
     *
     * @param method
     * @param thisObject
     * @param arguments
     * @param hookId
     */
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "copy"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "mismatch"
    )
    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.nio.file.Files",
            targetMethod = "move"
    )
    public static void copyMismatchMvHook(
            MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
        if (arguments.length > 1) {
            Object from = arguments[0];
            if (from instanceof Path) {
                checkPath((Path) from);
            }
            Object to = arguments[1];
            if (to instanceof Path) {
                checkPath((Path) to);
            }
        }
    }


    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.io.FileReader",
            targetMethod = "<init>"
    )
    public static void fileReaderHook(
            MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
        if (arguments.length > 0) {

            Object argObj = arguments[0];
            if (argObj instanceof String) {
                checkPath((String)argObj);
            } else if (argObj instanceof File) {
                checkPath((File)argObj);
            }
        }
    }

    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.io.FileWriter",
            targetMethod = "<init>"
    )
    public static void fileWriterHook(
            MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
        if (arguments.length > 0) {

            Object argObj = arguments[0];
            if (argObj instanceof String) {
                checkPath((String)argObj);
            } else if (argObj instanceof File) {
                checkPath((File)argObj);
            }
        }
    }



    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.io.FileInputStream",
            targetMethod = "<init>"
    )
    public static void fileInputStreamHook(
            MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
        if (arguments.length > 0) {

            Object argObj = arguments[0];
            if (argObj instanceof String) {
                checkPath((String)argObj);
            } else if (argObj instanceof File) {
                checkPath((File)argObj);
            }
        }
    }

    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.io.FileOutputStream",
            targetMethod = "<init>"
    )
    public static void processFileOutputStartHook(
            MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
        if (arguments.length > 0) {
            Object argObj = arguments[0];
            if (argObj instanceof File) {
                if (argObj instanceof String) {
                    checkPath((String)argObj);
                } else if (argObj instanceof File) {
                    checkPath((File)argObj);
                }
            }
        }
    }

    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.util.Scanner",
            targetMethod = "<init>"
    )
    public static void scannerHook(
            MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
        if (arguments.length > 0) {

            Object argObj = arguments[0];
            if (argObj instanceof String) {
                checkPath((String)argObj);
            } else if (argObj instanceof Path) {
                checkPath((Path)argObj);
            } else if (argObj instanceof File) {
                checkPath((File)argObj);
            }
        }
    }

    @MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.io.FileOutputStream",
            targetMethod = "<init>"
    )
    public static void fileOutputStreamHook(
            MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
        if (arguments.length > 0) {

            Object argObj = arguments[0];
            if (argObj instanceof File) {
                checkPath((File)argObj);
            } else if (argObj instanceof String) {
                checkPath((String)argObj);
            }
        }
    }

    private static void checkPath(File f) {
        try {
            checkPath(f.toPath());
        } catch (InvalidPathException e) {
            //TODO: give up -- for now
        }
    }

    private static void checkPath(String s) {
        try {
            checkPath(Paths.get(s));
        } catch (InvalidPathException e) {
            checkPath(new File(s));
        }
    }

    private static void checkPath(Path p) {
        if (p.getFileName().toString().equals(SENTINEL) && ! isAllowed(p)) {
            Jazzer.reportFindingFromHook(
                    new FuzzerSecurityIssueCritical("File path traversal: " + p));
        }
    }

    private static boolean isAllowed(Path candidate) {
        String allowedDirString = System.getProperty(ALLOWED_DIRS_KEY);

        if (allowedDirString == null || allowedDirString.trim().length() == 0) {
            return true;
        }

        Path candidateNormalized = candidate.toAbsolutePath().normalize();
        for (String pString : allowedDirString.split(",")) {
            Path allowedNormalized = Paths.get(pString).toAbsolutePath().normalize();
            if (candidateNormalized.startsWith(allowedNormalized) &&
                ! candidateNormalized.equals(allowedNormalized)) {
                return true;
            }
        }
        return false;
    }

}

