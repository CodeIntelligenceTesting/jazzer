/*
 * Copyright 2022 Code Intelligence GmbH
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

package com.code_intelligence.jazzer;

import static java.lang.System.exit;
import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;

import com.code_intelligence.jazzer.driver.Driver;
import com.github.fmeum.rules_jni.RulesJni;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

/**
 * The libFuzzer-compatible CLI entrypoint for Jazzer.
 *
 * <p>Arguments to Jazzer are passed as command-line arguments or {@code jazzer.*} system
 * properties. For example, setting the property {@code jazzer.target_class} to
 * {@code com.example.FuzzTest} is equivalent to passing the argument
 * {@code --target_class=com.example.FuzzTest}.
 *
 * <p>Arguments to libFuzzer are passed as command-line arguments.
 */
public class Jazzer {
  public static void main(String[] args) throws IOException, InterruptedException {
    start(Arrays.stream(args).collect(toList()));
  }

  // Accessed by jazzer_main.cpp.
  @SuppressWarnings("unused")
  private static void main(byte[][] nativeArgs) throws IOException, InterruptedException {
    start(Arrays.stream(nativeArgs)
              .map(bytes -> new String(bytes, StandardCharsets.UTF_8))
              .collect(toList()));
  }

  private static void start(List<String> args) throws IOException, InterruptedException {
    parseJazzerArgsToProperties(args);
    // --asan and --ubsan imply --native by default, but --native can also be used by itself to fuzz
    // native libraries without sanitizers (e.g. to quickly grow a corpus).
    final boolean loadASan = Boolean.parseBoolean(System.getProperty("jazzer.asan", "false"));
    final boolean loadUBSan = Boolean.parseBoolean(System.getProperty("jazzer.ubsan", "false"));
    final boolean fuzzNative = Boolean.parseBoolean(
        System.getProperty("jazzer.native", Boolean.toString(loadASan || loadUBSan)));
    if ((loadASan || loadUBSan) && !fuzzNative) {
      System.err.println("ERROR: --asan and --ubsan cannot be used without --native");
      exit(1);
    }
    // No native fuzzing has been requested, fuzz in the current process.
    if (!fuzzNative) {
      args =
          Stream.concat(Stream.of(prepareArgv0(new HashMap<>())), args.stream()).collect(toList());
      exit(Driver.start(args));
    }

    if (!isLinux() && !isMacOs()) {
      System.err.println(
          "ERROR: --asan, --ubsan, and --native are only supported on Linux and macOS");
      exit(1);
    }

    // Run ourselves as a subprocess with `jazzer_preload` and (optionally) native sanitizers
    // preloaded. By inheriting IO, this wrapping should become invisible for the user.
    Set<String> argsToFilter = Stream.of("--asan", "--ubsan", "--native").collect(toSet());
    ProcessBuilder processBuilder = new ProcessBuilder();
    List<Path> preloadLibs = new ArrayList<>();
    // We have to load jazzer_preload before we load ASan since the ASan includes no-op definitions
    // of the fuzzer callbacks as weak symbols, but the dynamic linker doesn't distinguish between
    // strong and weak symbols.
    preloadLibs.add(RulesJni.extractLibrary("jazzer_preload", Jazzer.class));
    if (loadASan) {
      processBuilder.environment().compute("ASAN_OPTIONS",
          (name, currentValue)
              -> appendWithPathListSeparator(name,
                  // The JVM produces an extremely large number of false positive leaks, which makes
                  // it impossible to use LeakSanitizer.
                  // TODO: Investigate whether we can hook malloc/free only for JNI shared
                  // libraries, not the JVM itself.
                  "detect_leaks=0",
                  // We load jazzer_preload first.
                  "verify_asan_link_order=0"));
      System.err.println(
          "WARN: Jazzer is not compatible with LeakSanitizer. Leaks are not reported.");
      preloadLibs.add(findHostClangLibrary(asanLibNames()));
    }
    if (loadUBSan) {
      preloadLibs.add(findHostClangLibrary(ubsanLibNames()));
    }
    // The launcher script we generate is executed by /bin/sh on macOS, which is codesigned without
    // the allow-dyld-environment-variables entitlement. The dynamic linker would thus remove all
    // DYLD_* variables. Instead, we pass these variables directly to the java executable by
    // emitting them into the wrapper. The java binary has both the allow-dyld-environment-variables
    // and the disable-library-validation entitlement, which allows any codesigned library to be
    // preloaded.
    processBuilder.environment().remove(preloadVariable());
    Map<String, String> additionalEnvironment = new HashMap<>();
    additionalEnvironment.put(preloadVariable(),
        appendWithPathListSeparator(
            preloadVariable(), preloadLibs.stream().map(Path::toString).toArray(String[] ::new)));
    List<String> subProcessArgs =
        Stream
            .concat(Stream.of(prepareArgv0(additionalEnvironment)),
                // Prevent a "fork bomb" by stripping all args that trigger this code path.
                args.stream().filter(arg -> !argsToFilter.contains(arg.split("=")[0])))
            .collect(toList());
    processBuilder.command(subProcessArgs);
    processBuilder.inheritIO();

    exit(processBuilder.start().waitFor());
  }

  private static void parseJazzerArgsToProperties(List<String> args) {
    args.stream()
        .filter(arg -> arg.startsWith("--"))
        .map(arg -> arg.substring("--".length()))
        // Filter out "--", which can be used to declare that all further arguments aren't libFuzzer
        // arguments.
        .filter(arg -> !arg.isEmpty())
        .map(Jazzer::parseSingleArg)
        .forEach(e -> System.setProperty("jazzer." + e.getKey(), e.getValue()));
  }

  private static SimpleEntry<String, String> parseSingleArg(String arg) {
    String[] nameAndValue = arg.split("=", 2);
    if (nameAndValue.length == 2) {
      // Example: --keep_going=10 --> (keep_going, 10)
      return new SimpleEntry<>(nameAndValue[0], nameAndValue[1]);
    } else if (nameAndValue[0].startsWith("no")) {
      // Example: --nohooks --> (hooks, "false")
      return new SimpleEntry<>(nameAndValue[0].substring("no".length()), "false");
    } else {
      // Example: --dedup --> (dedup, "true")
      return new SimpleEntry<>(nameAndValue[0], "true");
    }
  }

  // Create a wrapper script that faithfully recreates the current JVM. By using this script as
  // libFuzzer's argv[0], libFuzzer modes that rely on subprocesses can work with the Java driver.
  // This trick is also used to allow native sanitizers to be preloaded.
  private static String prepareArgv0(Map<String, String> additionalEnvironment) throws IOException {
    if (!isPosix() && !additionalEnvironment.isEmpty()) {
      throw new IllegalArgumentException(
          "Setting environment variables in the wrapper is only supported on POSIX systems");
    }
    char shellQuote = isPosix() ? '\'' : '"';
    String launcherTemplate = isPosix() ? "#!/usr/bin/env sh\n%s $@\n" : "@echo off\r\n%s %%*\r\n";
    String launcherExtension = isPosix() ? ".sh" : ".bat";
    FileAttribute<?>[] launcherScriptAttributes = isPosix()
        ? new FileAttribute[] {PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rwx------"))}
        : new FileAttribute[] {};
    String env = additionalEnvironment.entrySet()
                     .stream()
                     .map(e -> e.getKey() + "='" + e.getValue() + "'")
                     .collect(joining(" "));
    String command = Stream
                         .concat(Stream.of(javaBinary().toString()), javaBinaryArgs())
                         // Escape individual arguments for the shell.
                         .map(str -> shellQuote + str + shellQuote)
                         .collect(joining(" "));
    String invocation = env.isEmpty() ? command : env + " " + command;
    String launcherContent = String.format(launcherTemplate, invocation);
    Path launcher = Files.createTempFile("jazzer-", launcherExtension, launcherScriptAttributes);
    launcher.toFile().deleteOnExit();
    Files.write(launcher, launcherContent.getBytes(StandardCharsets.UTF_8));
    return launcher.toAbsolutePath().toString();
  }

  private static Path javaBinary() {
    return Paths.get(System.getProperty("java.home"), "bin", isPosix() ? "java" : "java.exe");
  }

  private static Stream<String> javaBinaryArgs() {
    return Stream.concat(ManagementFactory.getRuntimeMXBean().getInputArguments().stream(),
        Stream.of("-cp", System.getProperty("java.class.path"),
            // Make ByteBuddyAgent's job simpler by allowing it to attach directly to the JVM
            // rather than relying on an external helper. The latter fails on macOS 12 with JDK 11+
            // (but not 8) and UBSan preloaded with:
            // Caused by: java.io.IOException: Cannot run program
            // "/Users/runner/hostedtoolcache/Java_Zulu_jdk/17.0.4-8/x64/bin/java": error=0, Failed
            // to exec spawn helper: pid: 8227, signal: 9
            // Presumably, this issue is caused by codesigning and the exec helper missing the
            // entitlements required for library insertion.
            "-Djdk.attach.allowAttachSelf=true", Jazzer.class.getName()));
  }

  /**
   * Append the given elements to the value of the environment variable {@code name} that contains a
   * list of paths separated by the system path list separator.
   */
  private static String appendWithPathListSeparator(String name, String... options) {
    if (options.length == 0) {
      throw new IllegalArgumentException("options must not be empty");
    }

    String currentValue = Optional.ofNullable(System.getenv(name)).orElse("");
    String additionalOptions = String.join(File.pathSeparator, options);
    if (currentValue.isEmpty()) {
      return additionalOptions;
    }
    return currentValue + File.pathSeparator + additionalOptions;
  }

  private static Path findHostClangLibrary(List<String> candidateNames) {
    return candidateNames.stream()
        .map(Jazzer::tryFindHostClangLibrary)
        .filter(Optional::isPresent)
        .findFirst()
        .orElseGet(() -> {
          System.err.printf("ERROR: '%s' failed to find one of: %s%n", hostClang(),
              String.join(", ", candidateNames));
          exit(1);
          throw new IllegalStateException("not reached");
        })
        .get();
  }

  /**
   * Given a library name such as "libclang_rt.asan-x86_64.so", get the full path to the library
   * installed on the host from clang (or CC, if set). Returns Optional.empty() if clang does not
   * find the library and exits with a message in case of any other error condition.
   */
  private static Optional<Path> tryFindHostClangLibrary(String name) {
    List<String> command = asList(hostClang(), "--print-file-name", name);
    ProcessBuilder processBuilder = new ProcessBuilder(command);
    byte[] output;
    try {
      Process process = processBuilder.start();
      if (process.waitFor() != 0) {
        System.err.printf("ERROR: '%s' exited with exit code %d%n", String.join(" ", command),
            process.exitValue());
        copy(process.getInputStream(), System.out);
        copy(process.getErrorStream(), System.err);
        exit(1);
      }
      output = readAllBytes(process.getInputStream());
    } catch (IOException | InterruptedException e) {
      System.err.printf("ERROR: Failed to run '%s'%n", String.join(" ", command));
      e.printStackTrace();
      exit(1);
      throw new IllegalStateException("not reached");
    }
    Path library = Paths.get(new String(output).trim());
    if (Files.exists(library)) {
      return Optional.of(library);
    }
    return Optional.empty();
  }

  private static String hostClang() {
    return Optional.ofNullable(System.getenv("CC")).orElse("clang");
  }

  private static List<String> asanLibNames() {
    if (isLinux()) {
      // Since LLVM 15 sanitizer runtimes no longer have the architecture in the filename.
      return asList("libclang_rt.asan.so", "libclang_rt.asan-x86_64.so");
    } else {
      return singletonList("libclang_rt.asan_osx_dynamic.dylib");
    }
  }

  private static List<String> ubsanLibNames() {
    if (isLinux()) {
      return asList("libclang_rt.ubsan_standalone.so", "libclang_rt.ubsan_standalone-x86_64.so");
    } else {
      return singletonList("libclang_rt.ubsan_osx_dynamic.dylib");
    }
  }

  private static String preloadVariable() {
    return isLinux() ? "LD_PRELOAD" : "DYLD_INSERT_LIBRARIES";
  }

  private static boolean isLinux() {
    return System.getProperty("os.name").startsWith("Linux");
  }

  private static boolean isMacOs() {
    return System.getProperty("os.name").startsWith("Mac OS X");
  }

  private static boolean isPosix() {
    return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
  }

  private static byte[] readAllBytes(InputStream in) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    copy(in, out);
    return out.toByteArray();
  }

  private static void copy(InputStream source, OutputStream target) throws IOException {
    byte[] buffer = new byte[64 * 104 * 1024];
    int read;
    while ((read = source.read(buffer)) != -1) {
      target.write(buffer, 0, read);
    }
  }
}
