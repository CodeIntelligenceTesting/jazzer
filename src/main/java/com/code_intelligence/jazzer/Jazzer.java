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

package com.code_intelligence.jazzer;

import static com.code_intelligence.jazzer.Constants.JAZZER_VERSION;
import static com.code_intelligence.jazzer.runtime.Constants.IS_ANDROID;
import static java.lang.System.exit;
import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;

import com.code_intelligence.jazzer.android.AndroidRuntime;
import com.code_intelligence.jazzer.driver.Driver;
import com.code_intelligence.jazzer.driver.Opt;
import com.code_intelligence.jazzer.driver.junit.FuzzTestLister;
import com.code_intelligence.jazzer.driver.junit.JUnitRunner;
import com.code_intelligence.jazzer.utils.Log;
import com.code_intelligence.jazzer.utils.ZipUtils;
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
import java.util.AbstractMap.SimpleImmutableEntry;
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
 * properties. For example, setting the property {@code jazzer.target_class} to {@code
 * com.example.FuzzTest} is equivalent to passing the argument {@code
 * --target_class=com.example.FuzzTest}.
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
    start(
        Arrays.stream(nativeArgs)
            .map(bytes -> new String(bytes, StandardCharsets.UTF_8))
            .collect(toList()));
  }

  private static void start(List<String> args) throws IOException, InterruptedException {
    // Lock in the output PrintStreams so that Jazzer can still emit output even if the fuzz target
    // itself is "silenced" by redirecting System.out and/or System.err.
    Log.fixOutErr(System.out, System.err);

    Opt.registerAndValidateCommandLineArgs(parseJazzerArgs(args));
    handleTerminatingCommands();

    // --asan and --ubsan imply --native by default, but --native can also be used by itself to fuzz
    // native libraries without sanitizers (e.g. to quickly grow a corpus).
    final boolean loadASan = Opt.asan.get();
    final boolean loadUBSan = Opt.ubsan.get();
    final boolean loadHWASan = Opt.hwasan.get();
    final boolean needsNative = loadASan || loadUBSan || loadHWASan;
    Opt.fuzzNative.setIfDefault(needsNative);
    final boolean fuzzNative = Opt.fuzzNative.get();
    if (needsNative && !fuzzNative) {
      Log.error("--asan, --hwasan and --ubsan cannot be used without --native");
      exit(1);
    }
    // No native fuzzing has been requested, fuzz in the current process.
    if (!fuzzNative) {
      if (IS_ANDROID) {
        AndroidRuntime.initialize();
      }
      // We only create a wrapper script if libFuzzer runs in a mode that creates subprocesses.
      // In LibFuzzer's fork mode, the subprocesses created continuously by the main libFuzzer
      // process do not create further subprocesses. Creating a wrapper script for each subprocess
      // is an unnecessary overhead.
      final boolean spawnsSubprocesses =
          Stream.of("fork", "jobs", "merge", "minimize_crash")
              .anyMatch(option -> isLibFuzzerOptionEnabled(option, args));
      // argv0 is printed by libFuzzer during reproduction, so have it contain "jazzer".
      String arg0 = spawnsSubprocesses ? prepareArgv0(new HashMap<>()) : "jazzer";
      List<String> argsWithArgv0 = Stream.concat(Stream.of(arg0), args.stream()).collect(toList());
      exit(Driver.start(argsWithArgv0, spawnsSubprocesses));
    }

    if (!isLinux() && !isMacOs()) {
      Log.error("--asan, --ubsan, and --native are only supported on Linux and macOS");
      exit(1);
    }

    // Run ourselves as a subprocess with `jazzer_preload` and (optionally) native sanitizers
    // preloaded. By inheriting IO, this wrapping should become invisible for the user.
    Set<String> argsToFilter =
        Stream.of("--asan", "--ubsan", "--hwasan", "--native").collect(toSet());
    ProcessBuilder processBuilder = new ProcessBuilder();
    List<Path> preloadLibs = new ArrayList<>();
    // We have to load jazzer_preload before we load ASan since the ASan includes no-op definitions
    // of the fuzzer callbacks as weak symbols, but the dynamic linker doesn't distinguish between
    // strong and weak symbols.
    preloadLibs.add(RulesJni.extractLibrary("jazzer_preload", Jazzer.class));
    if (loadASan) {
      processBuilder
          .environment()
          .compute(
              "ASAN_OPTIONS",
              (name, currentValue) ->
                  appendWithPathListSeparator(
                      name,
                      // The JVM produces an extremely large number of false positive leaks, which
                      // makes
                      // it impossible to use LeakSanitizer.
                      // TODO: Investigate whether we can hook malloc/free only for JNI shared
                      // libraries, not the JVM itself.
                      "detect_leaks=0",
                      // We load jazzer_preload first.
                      "verify_asan_link_order=0"));
      Log.warn("Jazzer is not compatible with LeakSanitizer. Leaks are not reported.");
      preloadLibs.add(findLibrary(asanLibNames()));
    }
    if (loadHWASan) {
      processBuilder
          .environment()
          .compute(
              "HWASAN_OPTIONS",
              (name, currentValue) ->
                  appendWithPathListSeparator(
                      name,
                      // The JVM produces an extremely large number of false positive leaks, which
                      // makes
                      // it impossible to use LeakSanitizer.
                      // TODO: Investigate whether we can hook malloc/free only for JNI shared
                      // libraries, not the JVM itself.
                      "detect_leaks=0",
                      // We load jazzer_preload first.
                      "verify_asan_link_order=0"));
      Log.warn("Jazzer is not compatible with LeakSanitizer. Leaks are not reported.");
      preloadLibs.add(findLibrary(hwasanLibNames()));
    }
    if (loadUBSan) {
      preloadLibs.add(findLibrary(ubsanLibNames()));
    }
    // The launcher script we generate is executed by /bin/sh on macOS, which is codesigned without
    // the allow-dyld-environment-variables entitlement. The dynamic linker would thus remove all
    // DYLD_* variables. Instead, we pass these variables directly to the java executable by
    // emitting them into the wrapper. The java binary has both the allow-dyld-environment-variables
    // and the disable-library-validation entitlement, which allows any codesigned library to be
    // preloaded.
    processBuilder.environment().remove(preloadVariable());
    Map<String, String> additionalEnvironment = new HashMap<>();
    additionalEnvironment.put(
        preloadVariable(),
        appendWithPathListSeparator(
            preloadVariable(), preloadLibs.stream().map(Path::toString).toArray(String[]::new)));
    List<String> subProcessArgs =
        Stream.concat(
                Stream.of(prepareArgv0(additionalEnvironment)),
                // Prevent a "fork bomb" by stripping all args that trigger this code path.
                args.stream().filter(arg -> !argsToFilter.contains(arg.split("=")[0])))
            .collect(toList());
    processBuilder.command(subProcessArgs);
    processBuilder.inheritIO();

    exit(processBuilder.start().waitFor());
  }

  private static void handleTerminatingCommands() {
    if (Opt.help.get()) {
      Log.println(Opt.generateHelpText());
      exit(0);
    }
    if (Opt.version.get()) {
      Log.println("Jazzer v" + JAZZER_VERSION);
      exit(0);
    }
    if (Opt.listFuzzTests.isSet()) {
      handleListFuzzTests();
    }
  }

  private static void handleListFuzzTests() {
    if (JUnitRunner.isSupported()) {
      try {
        List<String> classes = Opt.listFuzzTests.get();
        List<String> fuzzTests = FuzzTestLister.listFuzzTests(classes);
        if (!fuzzTests.isEmpty()) {
          fuzzTests.forEach(Log::println);
          exit(0);
        } else {
          Log.error("Could not find any fuzz tests in " + classes);
        }
      } catch (RuntimeException e) {
        Log.error("Could not list fuzz tests", e);
      }
    } else {
      Log.error("Could not list fuzz tests, as JUnit is not available on the classpath");
    }
    exit(1);
  }

  private static List<Map.Entry<String, String>> parseJazzerArgs(List<String> args) {
    return args.stream()
        .filter(arg -> arg.startsWith("--"))
        .map(arg -> arg.substring("--".length()))
        // Filter out "--", which can be used to declare that all further arguments aren't libFuzzer
        // arguments.
        .filter(arg -> !arg.isEmpty())
        .map(Jazzer::parseSingleArg)
        .collect(toList());
  }

  private static SimpleImmutableEntry<String, String> parseSingleArg(String arg) {
    String[] nameAndValue = arg.split("=", 2);
    if (nameAndValue.length == 2) {
      // Example: --keep_going=10 --> (keep_going, 10)
      return new SimpleImmutableEntry<>(nameAndValue[0], nameAndValue[1]);
    } else if (nameAndValue[0].startsWith("no")) {
      // Example: --nohooks --> (hooks, "false")
      return new SimpleImmutableEntry<>(nameAndValue[0].substring("no".length()), "false");
    } else {
      // Example: --dedup --> (dedup, "true")
      return new SimpleImmutableEntry<>(nameAndValue[0], "true");
    }
  }

  /**
   * Returns whether the given libFuzzer option which isn't enabled by default is enabled by the
   * given command line.
   */
  static boolean isLibFuzzerOptionEnabled(String option, List<String> args) {
    return args.stream()
        .filter(arg -> arg.startsWith(String.format("-%s=", option)))
        .map(arg -> arg.split("=", 2)[1])
        // libFuzzer parses the value with strtol, which treats an empty value as 0.
        .map(value -> !value.isEmpty() && !value.equals("0"))
        // Later flags override earlier ones on the command line.
        .reduce(false, (prev, current) -> current);
  }

  // Create a wrapper script that faithfully recreates the current JVM. By using this script as
  // libFuzzer's argv[0], libFuzzer modes that rely on subprocesses can work with the Java driver.
  // This trick is also used to allow native sanitizers to be preloaded.
  private static String prepareArgv0(Map<String, String> additionalEnvironment) throws IOException {
    if (!isPosixOrAndroid() && !additionalEnvironment.isEmpty()) {
      throw new IllegalArgumentException(
          "Setting environment variables in the wrapper is only supported on POSIX systems and"
              + " Android");
    }
    char shellQuote = isPosixOrAndroid() ? '\'' : '"';
    String launcherTemplate;
    if (IS_ANDROID) {
      launcherTemplate = "#!/system/bin/env sh\n%s LD_LIBRARY_PATH=%s \n%s $@\n";
    } else if (isPosix()) {
      launcherTemplate = "#!/usr/bin/env sh\n%s $@\n";
    } else {
      launcherTemplate = "@echo off\r\n%s %%*\r\n";
    }

    String launcherExtension = isPosix() ? ".sh" : ".bat";
    FileAttribute<?>[] launcherScriptAttributes =
        isPosixOrAndroid()
            ? new FileAttribute[] {
              PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
            }
            : new FileAttribute[] {};
    String env =
        additionalEnvironment.entrySet().stream()
            .map(e -> e.getKey() + "='" + e.getValue() + "'")
            .collect(joining(" "));
    String command =
        Stream.concat(Stream.of(IS_ANDROID ? "exec" : javaBinary().toString()), javaBinaryArgs())
            // Escape individual arguments for the shell.
            .map(str -> shellQuote + str + shellQuote)
            .collect(joining(" "));

    String invocation = env.isEmpty() ? command : env + " " + command;

    // argv0 is printed by libFuzzer during reproduction, so have the launcher basename contain
    // "jazzer".
    Path launcher;
    String launcherContent;
    if (IS_ANDROID) {
      String exportCommand = AndroidRuntime.getClassPathsCommand();
      String ldLibraryPath = AndroidRuntime.getLdLibraryPath();
      launcherContent = String.format(launcherTemplate, exportCommand, ldLibraryPath, invocation);
      launcher =
          Files.createTempFile(
              Paths.get("/data/local/tmp/"),
              "jazzer-",
              launcherExtension,
              launcherScriptAttributes);
    } else {
      launcherContent = String.format(launcherTemplate, invocation);
      launcher = Files.createTempFile("jazzer-", launcherExtension, launcherScriptAttributes);
    }

    launcher.toFile().deleteOnExit();
    Files.write(launcher, launcherContent.getBytes(StandardCharsets.UTF_8));
    return launcher.toAbsolutePath().toString();
  }

  private static Path javaBinary() {
    String javaBinaryName;
    if (isPosix()) {
      javaBinaryName = "java";
    } else {
      javaBinaryName = "java.exe";
    }

    return Paths.get(System.getProperty("java.home"), "bin", javaBinaryName);
  }

  private static Stream<String> javaBinaryArgs() throws IOException {
    if (IS_ANDROID) {
      // Add Android specific args
      Path agentPath =
          RulesJni.extractLibrary("android_native_agent", "/com/code_intelligence/jazzer/android");

      String jazzerAgentPath = Opt.agentPath.get();
      String bootclassClassOverrides = Opt.androidBootclassClassesOverrides.get();

      String jazzerBootstrapJarPath =
          "com/code_intelligence/jazzer/android/jazzer_bootstrap_android.jar";
      String jazzerBootstrapJarOut = "/data/local/tmp/jazzer_bootstrap_android.jar";

      try {
        ZipUtils.extractFile(jazzerAgentPath, jazzerBootstrapJarPath, jazzerBootstrapJarOut);
      } catch (IOException ioe) {
        Log.error(
            "Could not extract jazzer_bootstrap_android.jar from Jazzer standalone agent", ioe);
        exit(1);
      }

      String nativeAgentOptions = "injectJars=" + jazzerBootstrapJarOut;
      if (bootclassClassOverrides != null && !bootclassClassOverrides.isEmpty()) {
        nativeAgentOptions += ",bootstrapClassOverrides=" + bootclassClassOverrides;
      }

      // ManagementFactory won't work with Android
      Stream<String> stream =
          Stream.of(
              "app_process",
              "-Djdk.attach.allowAttachSelf=true",
              "-Xplugin:libopenjdkjvmti.so",
              "-agentpath:" + agentPath.toString() + "=" + nativeAgentOptions,
              "-Xcompiler-option",
              "--debuggable",
              "/system/bin",
              Jazzer.class.getName());

      return stream;
    }

    Stream<String> stream =
        Stream.of(
            "-cp",
            System.getProperty("java.class.path"),
            // Make ByteBuddyAgent's job simpler by allowing it to attach directly to the JVM
            // rather than relying on an external helper. The latter fails on macOS 12 with JDK 11+
            // (but not 8) and UBSan preloaded with:
            // Caused by: java.io.IOException: Cannot run program
            // "/Users/runner/hostedtoolcache/Java_Zulu_jdk/17.0.4-8/x64/bin/java": error=0, Failed
            // to exec spawn helper: pid: 8227, signal: 9
            // Presumably, this issue is caused by codesigning and the exec helper missing the
            // entitlements required for library insertion.
            "-Djdk.attach.allowAttachSelf=true",
            Jazzer.class.getName());

    return Stream.concat(ManagementFactory.getRuntimeMXBean().getInputArguments().stream(), stream);
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

  private static Path findLibrary(List<String> candidateNames) {
    if (!IS_ANDROID) {
      return findHostClangLibrary(candidateNames);
    }

    for (String candidateName : candidateNames) {
      String candidateFullPath = "/apex/com.android.runtime/lib64/bionic/" + candidateName;
      File f = new File(candidateFullPath);
      if (f.exists()) {
        return Paths.get(candidateFullPath);
      }
    }

    Log.error(
        String.format("Failed to find one of %s%n for Android", String.join(", ", candidateNames)));
    Log.error("If fuzzing hwasan, make sure you have a hwasan build flashed to your device");

    exit(1);
    throw new IllegalStateException("not reached");
  }

  private static Path findHostClangLibrary(List<String> candidateNames) {
    for (String name : candidateNames) {
      Optional<Path> path = tryFindLibraryInJazzerNativeSanitizersDir(name);
      if (path.isPresent()) {
        return path.get();
      }
    }
    for (String name : candidateNames) {
      Optional<Path> path = tryFindLibraryUsingClang(name);
      if (path.isPresent()) {
        return path.get();
      }
    }
    Log.error("Failed to find one of: " + String.join(", ", candidateNames));
    exit(1);
    throw new IllegalStateException("not reached");
  }

  private static Optional<Path> tryFindLibraryInJazzerNativeSanitizersDir(String name) {
    String nativeSanitizersDir = System.getenv("JAZZER_NATIVE_SANITIZERS_DIR");
    if (nativeSanitizersDir == null) {
      return Optional.empty();
    }
    Path candidatePath = Paths.get(nativeSanitizersDir, name);
    if (Files.exists(candidatePath)) {
      return Optional.of(candidatePath);
    } else {
      return Optional.empty();
    }
  }

  /**
   * Given a library name such as "libclang_rt.asan-x86_64.so", get the full path to the library
   * installed on the host from clang (or CC, if set). Returns Optional.empty() if clang does not
   * find the library and exits with a message in case of any other error condition.
   */
  private static Optional<Path> tryFindLibraryUsingClang(String name) {
    List<String> command = asList(hostClang(), "--print-file-name", name);
    ProcessBuilder processBuilder = new ProcessBuilder(command);
    byte[] output;
    try {
      Process process = processBuilder.start();
      if (process.waitFor() != 0) {
        Log.error(
            String.format(
                "'%s' exited with exit code %d", String.join(" ", command), process.exitValue()));
        copy(process.getInputStream(), System.out);
        copy(process.getErrorStream(), System.err);
        exit(1);
      }
      output = readAllBytes(process.getInputStream());
    } catch (IOException | InterruptedException e) {
      Log.error(String.format("Failed to run '%s'", String.join(" ", command)), e);
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

  private static List<String> hwasanLibNames() {
    if (!IS_ANDROID) {
      Log.error("HWAsan is only supported for Android. Please try --asan");
      exit(1);
    }

    return singletonList("libclang_rt.hwasan-aarch64-android.so");
  }

  private static List<String> asanLibNames() {
    if (isLinux()) {
      if (IS_ANDROID) {
        Log.error(
            "ASan is not supported for Android at this time. Use --hwasan for Address "
                + "Sanitization on Android");
        exit(1);
      }

      // Since LLVM 15 sanitizer runtimes no longer have the architecture in the filename.
      return asList("libclang_rt.asan.so", "libclang_rt.asan-x86_64.so");
    } else {
      return singletonList("libclang_rt.asan_osx_dynamic.dylib");
    }
  }

  private static List<String> ubsanLibNames() {
    if (isLinux()) {
      if (IS_ANDROID) {
        // return asList("libclang_rt.ubsan_standalone-aarch64-android.so");
        Log.error("ERROR: UBSan is not supported for Android at this time.");
        exit(1);
      }

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
    return !IS_ANDROID && FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
  }

  private static boolean isPosixOrAndroid() {
    if (isPosix()) {
      return true;
    }
    return IS_ANDROID;
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
