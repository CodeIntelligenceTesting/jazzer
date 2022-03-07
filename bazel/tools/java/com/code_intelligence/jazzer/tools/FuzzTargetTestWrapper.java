// Copyright 2021 Code Intelligence GmbH
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

import com.google.devtools.build.runfiles.Runfiles;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.tools.JavaCompiler;
import javax.tools.JavaCompiler.CompilationTask;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

public class FuzzTargetTestWrapper {
  private static final boolean JAZZER_CI = "1".equals(System.getenv("JAZZER_CI"));

  public static void main(String[] args) {
    Runfiles runfiles;
    String driverActualPath;
    String apiActualPath;
    String jarActualPath;
    boolean verifyCrashInput;
    boolean verifyCrashReproducer;
    Set<String> expectedFindings;
    try {
      runfiles = Runfiles.create();
      driverActualPath = lookUpRunfile(runfiles, args[0]);
      apiActualPath = lookUpRunfile(runfiles, args[1]);
      jarActualPath = lookUpRunfile(runfiles, args[2]);
      verifyCrashInput = Boolean.parseBoolean(args[3]);
      verifyCrashReproducer = Boolean.parseBoolean(args[4]);
      expectedFindings =
          Arrays.stream(args[5].split(",")).filter(s -> !s.isEmpty()).collect(Collectors.toSet());
    } catch (IOException | ArrayIndexOutOfBoundsException e) {
      e.printStackTrace();
      System.exit(1);
      return;
    }

    ProcessBuilder processBuilder = new ProcessBuilder();
    Map<String, String> environment = processBuilder.environment();
    // Ensure that Jazzer can find its runfiles.
    environment.putAll(runfiles.getEnvVars());

    // Crashes will be available as test outputs. These are cleared on the next run,
    // so this is only useful for examples.
    String outputDir = System.getenv("TEST_UNDECLARED_OUTPUTS_DIR");

    // Map all files/dirs to real location
    Stream<String> arguments = Arrays.stream(args).skip(6).map(
        arg -> arg.startsWith("-") ? arg : lookUpRunfileWithFallback(runfiles, arg));

    List<String> command =
        Stream
            .concat(Stream.of(driverActualPath, String.format("-artifact_prefix=%s/", outputDir),
                        String.format("--reproducer_path=%s", outputDir), "-seed=2735196724",
                        String.format("--cp=%s", jarActualPath)),
                arguments)
            .collect(Collectors.toList());
    processBuilder.inheritIO();
    processBuilder.command(command);

    try {
      int exitCode = processBuilder.start().waitFor();
      // Assert that we either found a crash in Java (exit code 77) or a sanitizer crash (exit code
      // 76).
      if (exitCode != 76 && exitCode != 77) {
        System.exit(3);
      }
      String[] outputFiles = new File(outputDir).list();
      if (outputFiles == null) {
        System.exit(4);
      }
      // Verify that libFuzzer dumped a crashing input.
      if (JAZZER_CI && verifyCrashInput
          && Arrays.stream(outputFiles).noneMatch(name -> name.startsWith("crash-"))) {
        System.out.printf("No crashing input found in %s%n", outputDir);
        System.exit(5);
      }
      // Verify that libFuzzer dumped a crash reproducer.
      if (JAZZER_CI && verifyCrashReproducer
          && Arrays.stream(outputFiles).noneMatch(name -> name.startsWith("Crash_"))) {
        System.out.printf("No crash reproducer found in %s%n", outputDir);
        System.exit(6);
      }
    } catch (IOException | InterruptedException e) {
      e.printStackTrace();
      System.exit(2);
    }

    if (JAZZER_CI && verifyCrashReproducer) {
      try {
        verifyCrashReproducer(
            outputDir, driverActualPath, apiActualPath, jarActualPath, expectedFindings);
      } catch (Exception e) {
        e.printStackTrace();
        System.exit(6);
      }
    }
    System.exit(0);
  }

  // Looks up a Bazel "rootpath" in this binary's runfiles and returns the resulting path.
  private static String lookUpRunfile(Runfiles runfiles, String rootpath) {
    return runfiles.rlocation(rlocationPath(rootpath));
  }

  // Looks up a Bazel "rootpath" in this binary's runfiles and returns the resulting path if it
  // exists. If not, returns the original path unmodified.
  private static String lookUpRunfileWithFallback(Runfiles runfiles, String rootpath) {
    String candidatePath;
    try {
      candidatePath = lookUpRunfile(runfiles, rootpath);
    } catch (IllegalArgumentException unused) {
      // The argument to Runfiles.rlocation had an invalid format, which indicates that rootpath
      // is not a Bazel "rootpath" but a user-supplied path that should be returned unchanged.
      return rootpath;
    }
    if (new File(candidatePath).exists()) {
      return candidatePath;
    } else {
      return rootpath;
    }
  }

  // Turns the result of Bazel's `$(rootpath ...)` into the correct format for rlocation.
  private static String rlocationPath(String rootpath) {
    if (rootpath.startsWith("external/")) {
      return rootpath.substring("external/".length());
    } else {
      return "jazzer/" + rootpath;
    }
  }

  private static void verifyCrashReproducer(String outputDir, String driver, String api, String jar,
      Set<String> expectedFindings) throws Exception {
    File source =
        Files.list(Paths.get(outputDir))
            .filter(f -> f.toFile().getName().endsWith(".java"))
            // Verify the crash reproducer that was created last in order to reproduce the last
            // crash when using --keep_going.
            .max(Comparator.comparingLong(p -> p.toFile().lastModified()))
            .map(Path::toFile)
            .orElseThrow(
                () -> new IllegalStateException("Could not find crash reproducer in " + outputDir));
    String crashReproducer = compile(source, driver, api, jar);
    execute(crashReproducer, outputDir, expectedFindings);
  }

  private static String compile(File source, String driver, String api, String jar)
      throws IOException {
    JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    try (StandardJavaFileManager fileManager = compiler.getStandardFileManager(null, null, null)) {
      Iterable<? extends JavaFileObject> compilationUnits = fileManager.getJavaFileObjects(source);
      List<String> options =
          Arrays.asList("-classpath", String.join(File.pathSeparator, driver, api, jar));
      System.out.printf(
          "Compile crash reproducer %s with options %s%n", source.getAbsolutePath(), options);
      CompilationTask task =
          compiler.getTask(null, fileManager, null, options, null, compilationUnits);
      if (!task.call()) {
        throw new IllegalStateException("Could not compile crash reproducer " + source);
      }
      return source.getName().substring(0, source.getName().indexOf("."));
    }
  }

  private static void execute(String classFile, String outputDir, Set<String> expectedFindings)
      throws IOException, ReflectiveOperationException {
    try {
      System.out.printf("Execute crash reproducer %s%n", classFile);
      URLClassLoader classLoader =
          new URLClassLoader(new URL[] {new URL("file://" + outputDir + "/")});
      Class<?> crashReproducerClass = classLoader.loadClass(classFile);
      Method main = crashReproducerClass.getMethod("main", String[].class);
      System.setProperty("jazzer.is_reproducer", "true");
      main.invoke(null, new Object[] {new String[] {}});
      if (!expectedFindings.isEmpty()) {
        throw new IllegalStateException("Expected crash with any of "
            + String.join(", ", expectedFindings) + " not reproduced by " + classFile);
      }
    } catch (InvocationTargetException e) {
      // expect the invocation to fail with the prescribed finding
      Throwable finding = e.getCause();
      if (expectedFindings.isEmpty()) {
        throw new IllegalStateException("Did not expect " + classFile + " to crash", finding);
      } else if (expectedFindings.contains(finding.getClass().getName())) {
        System.out.printf("Reproduced exception \"%s\"%n", finding.getMessage());
      } else {
        throw new IllegalStateException(
            classFile + " did not crash with any of " + String.join(", ", expectedFindings),
            finding);
      }
    }
  }
}
