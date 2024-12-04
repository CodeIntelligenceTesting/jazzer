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

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableSet;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;

import com.google.devtools.build.runfiles.AutoBazelRepository;
import com.google.devtools.build.runfiles.Runfiles;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.ProcessBuilder.Redirect;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.tools.JavaCompiler;
import javax.tools.JavaCompiler.CompilationTask;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

@AutoBazelRepository
public class FuzzTargetTestWrapper {
  private static final Set<String> IGNORED_WARNINGS =
      // Triggered by BatikTranscoderFuzzer on macOS in Github Actions.
      Collections.singleton("WARNING: GL pipe is running in software mode (Renderer ID=0x1020400)");
  private static final String EXCEPTION_PREFIX = "== Java Exception: ";
  private static final String FRAME_PREFIX = "\tat ";
  private static final Pattern SANITIZER_FINDING = Pattern.compile("^SUMMARY: \\w*Sanitizer");
  private static final String THREAD_DUMP_HEADER = "Stack traces of all JVM threads:";
  private static final Set<String> PUBLIC_JAZZER_PACKAGES =
      unmodifiableSet(Stream.of("api", "replay", "sanitizers").collect(toSet()));

  public static void main(String[] args) {
    Runfiles runfiles;
    Path driverActualPath;
    Path apiActualPath;
    Path targetJarActualPath;
    Path hookJarActualPath;
    boolean shouldVerifyCrashInput;
    boolean shouldVerifyCrashReproducer;
    boolean expectCrash;
    int expectNonCrashExitCode;
    boolean usesJavaLauncher;
    int expectedNumberOfFindings;
    Optional<String> expectedWarningOrError;
    Set<String> allowedFindings;
    List<String> arguments;
    try {
      runfiles =
          Runfiles.preload().withSourceRepository(AutoBazelRepository_FuzzTargetTestWrapper.NAME);
      driverActualPath = Paths.get(runfiles.rlocation(args[0]));
      apiActualPath = Paths.get(runfiles.rlocation(args[1]));
      targetJarActualPath = Paths.get(runfiles.rlocation(args[2]));
      hookJarActualPath = args[3].isEmpty() ? null : Paths.get(runfiles.rlocation(args[3]));
      shouldVerifyCrashInput = Boolean.parseBoolean(args[4]);
      shouldVerifyCrashReproducer = Boolean.parseBoolean(args[5]);
      expectCrash = Boolean.parseBoolean(args[6]);
      expectNonCrashExitCode = Integer.parseInt(args[7]);
      usesJavaLauncher = Boolean.parseBoolean(args[8]);
      expectedNumberOfFindings = Integer.parseInt(args[9]);
      expectedWarningOrError = args[10].isEmpty() ? Optional.empty() : Optional.of(args[10]);
      allowedFindings =
          Arrays.stream(args[11].split(",")).filter(s -> !s.isEmpty()).collect(toSet());
      // Map all files/dirs to real location
      arguments =
          Arrays.stream(args)
              .skip(12)
              .map(arg -> arg.startsWith("-") ? arg : runfiles.rlocation(arg))
              .collect(toList());
    } catch (IOException | ArrayIndexOutOfBoundsException e) {
      e.printStackTrace();
      System.exit(1);
      return;
    }

    if (expectedNumberOfFindings > 1
        && (allowedFindings.contains("timeout") || allowedFindings.contains("native"))) {
      throw new IllegalArgumentException("Cannot expect multiple native or timeout findings");
    }

    ProcessBuilder processBuilder = new ProcessBuilder();
    // Ensure that Jazzer can find its runfiles.
    processBuilder.environment().putAll(runfiles.getEnvVars());
    // Ensure that sanitizers behave consistently across OSes and use a dedicated exit code to make
    // them distinguishable from unexpected crashes.
    processBuilder.environment().put("ASAN_OPTIONS", "abort_on_error=0:exitcode=76");
    processBuilder.environment().put("UBSAN_OPTIONS", "abort_on_error=0:exitcode=76");

    // Crashes will be available as test outputs. These are cleared on the next run,
    // so this is only useful for examples.
    Path outputDir = Paths.get(System.getenv("TEST_UNDECLARED_OUTPUTS_DIR"));

    List<String> command = new ArrayList<>();
    command.add(driverActualPath.toString());
    if (usesJavaLauncher) {
      if (hookJarActualPath != null) {
        command.add(String.format("--main_advice_classpath=%s", hookJarActualPath));
      }
      command.add(
          "--jvm_flags="
              + String.join(
                  " ",
                  "-XX:-OmitStackTraceInFastThrow",
                  "-XX:+UseParallelGC",
                  "-XX:+IgnoreUnrecognizedVMOptions",
                  "-XX:+CriticalJNINatives",
                  "-XX:+EnableDynamicAgentLoading"));
      if (System.getenv("JAZZER_DEBUG") != null && System.getenv("JAZZER_DEBUG").equals("1")) {
        command.add("--debug");
      }
    } else {
      command.add(
          String.format(
              "--cp=%s",
              hookJarActualPath == null
                  ? targetJarActualPath
                  : String.join(
                      System.getProperty("path.separator"),
                      targetJarActualPath.toString(),
                      hookJarActualPath.toString())));
    }
    command.add(String.format("-artifact_prefix=%s/", outputDir));
    command.add(String.format("--reproducer_path=%s", outputDir));
    if (System.getenv("JAZZER_NO_EXPLICIT_SEED") == null) {
      command.add("-seed=2735196724");
    }
    command.addAll(arguments);

    // Make JVM error reports available in test outputs.
    processBuilder
        .environment()
        .put("JAVA_TOOL_OPTIONS", String.format("-XX:ErrorFile=%s/hs_err_pid%%p.log", outputDir));
    processBuilder.redirectOutput(Redirect.INHERIT);
    processBuilder.redirectInput(Redirect.INHERIT);
    processBuilder.command(command);

    try {
      Process process = processBuilder.start();
      boolean sawErrorWithStackTrace;
      try {
        sawErrorWithStackTrace =
            verifyFuzzerOutput(
                process.getErrorStream(),
                allowedFindings,
                arguments.contains("--nohooks"),
                expectedWarningOrError,
                expectedNumberOfFindings);
      } finally {
        process.getErrorStream().close();
      }
      int exitCode = process.waitFor();
      if (!expectCrash) {
        if (expectNonCrashExitCode >= 0) {
          if (expectNonCrashExitCode != exitCode) {
            System.err.printf(
                "Expected exit code %d, but Jazzer exited with exit code %d%n",
                expectNonCrashExitCode, exitCode);
            System.exit(1);
          }
        } else if (exitCode != 0) {
          System.err.printf(
              "Did not expect a crash, but Jazzer exited with exit code %d%n", exitCode);
          System.exit(1);
        }
        System.exit(0);
      }
      // Assert that we either found a crash in Java (exit code 77), a sanitizer crash (exit code
      // 76), a timeout (exit code 70) or an error with stack trace (exit code 1).
      if (exitCode != 76
          && exitCode != 77
          && !(allowedFindings.contains("timeout") && exitCode == 70)
          && !(sawErrorWithStackTrace && exitCode == 1)) {
        System.err.printf("Did expect a crash, but Jazzer exited with exit code %d%n", exitCode);
        System.exit(1);
      }
      List<Path> outputFiles = Files.list(outputDir).collect(toList());
      // Verify that libFuzzer dumped a crashing input.
      if (shouldVerifyCrashInput
          && outputFiles.stream()
              .noneMatch(name -> name.getFileName().toString().startsWith("crash-"))
          && !(allowedFindings.contains("timeout")
              && outputFiles.stream()
                  .anyMatch(name -> name.getFileName().toString().startsWith("timeout-")))) {
        System.err.printf("No crashing input found in %s%n", outputDir);
        System.exit(1);
      }
      // Verify that libFuzzer dumped a crash reproducer.
      if (shouldVerifyCrashReproducer
          && outputFiles.stream()
              .noneMatch(name -> name.getFileName().toString().startsWith("Crash_"))) {
        System.err.printf("No crash reproducer found in %s%n", outputDir);
        System.exit(1);
      }
    } catch (IOException | InterruptedException e) {
      e.printStackTrace();
      System.exit(1);
    }

    if (shouldVerifyCrashReproducer) {
      try {
        verifyCrashReproducer(outputDir, apiActualPath, targetJarActualPath, allowedFindings);
      } catch (Exception e) {
        e.printStackTrace();
        System.exit(1);
      }
    }
    System.exit(0);
  }

  // Returns true if the fuzzer failed with an error and there was a stack trace.
  private static boolean verifyFuzzerOutput(
      InputStream fuzzerOutput,
      Set<String> expectedFindings,
      boolean noHooks,
      Optional<String> expectedWarningOrError,
      int expectedNumberOfFindings)
      throws IOException {
    List<String> lines;
    try (BufferedReader reader = new BufferedReader(new InputStreamReader(fuzzerOutput))) {
      // Print the lines as they are read to get live updates on the console.
      lines = reader.lines().peek(System.err::println).collect(toList());
    }

    List<String> warningsAndErrors =
        lines.stream()
            .filter(line -> line.startsWith("WARN") || line.startsWith("ERROR"))
            .filter(line -> !IGNORED_WARNINGS.contains(line))
            .collect(toList());
    boolean sawError = warningsAndErrors.stream().anyMatch(line -> line.startsWith("ERROR"));
    if (!expectedWarningOrError.isPresent() && !warningsAndErrors.isEmpty()) {
      throw new IllegalStateException(
          "Did not expect warnings or errors, but got:\n" + String.join("\n", warningsAndErrors));
    }
    if (expectedWarningOrError.isPresent()) {
      if (warningsAndErrors.isEmpty()) {
        throw new IllegalStateException("Expected a warning or error, but did not get any");
      }
      String unexpectedWarningsAndErrors =
          warningsAndErrors.stream()
              .filter(line -> !line.matches(expectedWarningOrError.get() + ".*$"))
              .collect(Collectors.joining("\n"));
      if (!unexpectedWarningsAndErrors.isEmpty()) {
        throw new IllegalStateException(
            "Got unexpected warnings or errors: " + unexpectedWarningsAndErrors);
      }
    }

    List<String> stackTrace =
        lines.stream()
            .filter(
                line ->
                    line.startsWith(EXCEPTION_PREFIX)
                        || line.startsWith(FRAME_PREFIX)
                        || line.equals(THREAD_DUMP_HEADER)
                        || SANITIZER_FINDING.matcher(line).find())
            .collect(toList());
    if (expectedFindings.isEmpty()) {
      if (stackTrace.isEmpty()) {
        return false;
      }
      if (!warningsAndErrors.isEmpty()) {
        return sawError;
      }
      throw new IllegalStateException(
          String.format(
              "Did not expect a finding, but got a stack trace:%n%s",
              String.join("\n", stackTrace)));
    }
    if (expectedFindings.contains("native")) {
      // Expect a native sanitizer finding as well as a thread dump with at least one frame.
      if (stackTrace.stream().noneMatch(line -> SANITIZER_FINDING.matcher(line).find())) {
        throw new IllegalStateException("Expected native sanitizer finding, but did not get any");
      }
      if (!stackTrace.contains(THREAD_DUMP_HEADER) || stackTrace.size() < 3) {
        throw new IllegalStateException(
            "Expected stack traces for all threads, but did not get any");
      }
      if (expectedFindings.size() != 1) {
        throw new IllegalStateException("Cannot expect both a native and other findings");
      }
      return false;
    }
    if (expectedFindings.contains("timeout")) {
      if (!stackTrace.contains(THREAD_DUMP_HEADER) || stackTrace.size() < 3) {
        throw new IllegalStateException(
            "Expected stack traces for all threads, but did not get any");
      }
      if (expectedFindings.size() != 1) {
        throw new IllegalStateException("Cannot expect both a timeout and other findings");
      }
      return false;
    }
    List<String> findings =
        stackTrace.stream()
            .filter(line -> line.startsWith(EXCEPTION_PREFIX))
            .map(line -> line.substring(EXCEPTION_PREFIX.length()).split(":", 2)[0])
            .collect(toList());
    if (findings.isEmpty()) {
      throw new IllegalStateException("Expected a crash, but did not get a stack trace");
    }
    if (expectedNumberOfFindings > 0 && (findings.size() != expectedNumberOfFindings)) {
      throw new IllegalStateException(
          String.format(
              "Expected %d findings, but got %d:%n%s",
              expectedNumberOfFindings, findings.size(), String.join("\n", findings)));
    }
    for (String finding : findings) {
      if (!expectedFindings.contains(finding)) {
        throw new IllegalStateException(
            String.format(
                "Got finding %s, but expected one of: %s",
                finding, String.join(", ", expectedFindings)));
      }
    }
    List<String> unexpectedFrames =
        stackTrace.stream()
            .filter(line -> line.startsWith(FRAME_PREFIX))
            .map(line -> line.substring(FRAME_PREFIX.length()))
            .filter(line -> line.startsWith("com.code_intelligence.jazzer."))
            // With --nohooks, Jazzer does not filter out its own stack frames.
            .filter(
                line ->
                    !noHooks
                        && !PUBLIC_JAZZER_PACKAGES.contains(
                            line.substring("com.code_intelligence.jazzer.".length())
                                .split("\\.")[0]))
            .collect(toList());
    if (!unexpectedFrames.isEmpty()) {
      throw new IllegalStateException(
          String.format(
              "Unexpected strack trace frames:%n%n%s%n%nin:%n%s",
              String.join("\n", unexpectedFrames), String.join("\n", stackTrace)));
    }
    return false;
  }

  private static void verifyCrashReproducer(
      Path outputDir, Path api, Path targetJar, Set<String> expectedFindings) throws Exception {
    File source =
        Files.list(outputDir)
            .filter(f -> f.toFile().getName().endsWith(".java"))
            // Verify the crash reproducer that was created last in order to reproduce the last
            // crash when using --keep_going.
            .max(Comparator.comparingLong(p -> p.toFile().lastModified()))
            .map(Path::toFile)
            .orElseThrow(
                () -> new IllegalStateException("Could not find crash reproducer in " + outputDir));
    String reproducerClassName = compile(source, api, targetJar);
    execute(reproducerClassName, outputDir, api, targetJar, expectedFindings);
  }

  private static String compile(File source, Path api, Path targetJar) throws IOException {
    JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    try (StandardJavaFileManager fileManager = compiler.getStandardFileManager(null, null, null)) {
      Iterable<? extends JavaFileObject> compilationUnits = fileManager.getJavaFileObjects(source);
      List<String> options =
          asList(
              "-classpath", String.join(File.pathSeparator, api.toString(), targetJar.toString()));
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

  private static void execute(
      String className, Path outputDir, Path api, Path targetJar, Set<String> expectedFindings)
      throws IOException, ReflectiveOperationException {
    try {
      System.out.printf("Execute crash reproducer %s%n", className);
      URLClassLoader classLoader =
          new URLClassLoader(
              new URL[] {
                outputDir.toUri().toURL(), api.toUri().toURL(), targetJar.toUri().toURL(),
              },
              getPlatformClassLoader());
      Class<?> crashReproducerClass = classLoader.loadClass(className);
      Method main = crashReproducerClass.getMethod("main", String[].class);
      System.setProperty("jazzer.is_reproducer", "true");
      main.invoke(null, new Object[] {new String[] {}});
      if (!expectedFindings.isEmpty()) {
        throw new IllegalStateException(
            "Expected crash with any of "
                + String.join(", ", expectedFindings)
                + " not reproduced by "
                + className);
      }
      System.out.println("Reproducer finished successfully without finding");
    } catch (InvocationTargetException e) {
      // expect the invocation to fail with the prescribed finding
      Throwable finding = e.getCause();
      if (expectedFindings.isEmpty()) {
        throw new IllegalStateException("Did not expect " + className + " to crash", finding);
      } else if (expectedFindings.contains(finding.getClass().getName())) {
        System.out.printf("Reproduced exception \"%s\"%n", finding);
      } else {
        throw new IllegalStateException(
            className + " did not crash with any of " + String.join(", ", expectedFindings),
            finding);
      }
    }
  }

  private static ClassLoader getPlatformClassLoader() {
    try {
      Method getter = ClassLoader.class.getMethod("getPlatformClassLoader");
      // Java 9 and higher
      return (ClassLoader) getter.invoke(null);
    } catch (NoSuchMethodException e) {
      // Java 8: All standard library classes are visible through the ClassLoader represented by
      // null.
      return null;
    } catch (InvocationTargetException | IllegalAccessException e) {
      throw new RuntimeException(e);
    }
  }
}
