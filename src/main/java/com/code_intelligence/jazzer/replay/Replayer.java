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

package com.code_intelligence.jazzer.replay;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.driver.FuzzedDataProviderImpl;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

public class Replayer {
  public static final int STATUS_FINDING = 77;
  public static final int STATUS_OTHER_ERROR = 1;

  public static void main(String[] args) {
    if (args.length < 2) {
      System.err.println("Usage: <fuzz target class> <input file path> <fuzzerInitialize args>...");
      System.exit(STATUS_OTHER_ERROR);
    }
    ClassLoader.getSystemClassLoader().setDefaultAssertionStatus(true);

    Class<?> fuzzTargetClass;
    try {
      fuzzTargetClass = Class.forName(args[0]);
    } catch (ClassNotFoundException e) {
      e.printStackTrace();
      System.exit(STATUS_OTHER_ERROR);
      // Without this return the compiler sees fuzzTargetClass as possibly uninitialized.
      return;
    }

    String inputFilePath = args[1];
    byte[] input = loadInput(inputFilePath);

    String[] fuzzTargetArgs = Arrays.copyOfRange(args, 2, args.length);
    executeFuzzerInitialize(fuzzTargetClass, fuzzTargetArgs);
    executeFuzzTarget(fuzzTargetClass, input);
  }

  private static byte[] loadInput(String inputFilePath) {
    try {
      return Files.readAllBytes(Paths.get(inputFilePath));
    } catch (IOException e) {
      e.printStackTrace();
      System.exit(STATUS_OTHER_ERROR);
      // Without this return the compiler sees loadInput as possibly not returning a value.
      return null;
    }
  }

  private static void executeFuzzerInitialize(Class<?> fuzzTarget, String[] args) {
    // public static void fuzzerInitialize()
    try {
      Method fuzzerInitialize = fuzzTarget.getMethod("fuzzerInitialize");
      fuzzerInitialize.invoke(null);
      return;
    } catch (Exception e) {
      handleInvokeException(e, fuzzTarget);
    }
    // public static void fuzzerInitialize(String[] args)
    try {
      Method fuzzerInitialize = fuzzTarget.getMethod("fuzzerInitialize", String[].class);
      fuzzerInitialize.invoke(null, (Object) args);
    } catch (Exception e) {
      handleInvokeException(e, fuzzTarget);
    }
  }

  public static void executeFuzzTarget(Class<?> fuzzTarget, byte[] input) {
    // public static void fuzzerTestOneInput(byte[] input)
    try {
      Method fuzzerTestOneInput = fuzzTarget.getMethod("fuzzerTestOneInput", byte[].class);
      fuzzerTestOneInput.invoke(null, (Object) input);
      return;
    } catch (Exception e) {
      handleInvokeException(e, fuzzTarget);
    }
    // public static void fuzzerTestOneInput(FuzzedDataProvider data)
    try {
      Method fuzzerTestOneInput =
          fuzzTarget.getMethod("fuzzerTestOneInput", FuzzedDataProvider.class);
      try (FuzzedDataProviderImpl fuzzedDataProvider = FuzzedDataProviderImpl.withJavaData(input)) {
        fuzzerTestOneInput.invoke(null, fuzzedDataProvider);
      }
      return;
    } catch (Exception e) {
      handleInvokeException(e, fuzzTarget);
    }
    System.err.printf(
        "%s must define exactly one of the following two functions:%n"
            + "    public static void fuzzerTestOneInput(byte[] ...)%n"
            + "    public static void fuzzerTestOneInput(FuzzedDataProvider ...)%n"
            + "Note: Fuzz targets returning boolean are no longer supported; exceptions should%n"
            + "be thrown instead of returning true.%n",
        fuzzTarget.getName());
    System.exit(STATUS_OTHER_ERROR);
  }

  private static void handleInvokeException(Exception e, Class<?> fuzzTarget) {
    if (e instanceof NoSuchMethodException) return;
    if (e instanceof InvocationTargetException) {
      filterOutOwnStackTraceElements(e.getCause(), fuzzTarget);
      e.getCause().printStackTrace();
      System.exit(STATUS_FINDING);
    } else {
      e.printStackTrace();
      System.exit(STATUS_OTHER_ERROR);
    }
  }

  private static void filterOutOwnStackTraceElements(Throwable t, Class<?> fuzzTarget) {
    if (t.getCause() != null) filterOutOwnStackTraceElements(t.getCause(), fuzzTarget);
    if (t.getStackTrace() == null || t.getStackTrace().length == 0) return;
    StackTraceElement lowestFrame = t.getStackTrace()[t.getStackTrace().length - 1];
    if (!lowestFrame.getClassName().equals(Replayer.class.getName())
        || !lowestFrame.getMethodName().equals("main")) return;
    for (int i = t.getStackTrace().length - 1; i >= 0; i--) {
      StackTraceElement frame = t.getStackTrace()[i];
      if (frame.getClassName().equals(fuzzTarget.getName())
          && frame.getMethodName().equals("fuzzerTestOneInput")) {
        t.setStackTrace(Arrays.copyOfRange(t.getStackTrace(), 0, i + 1));
        break;
      }
    }
  }
}
