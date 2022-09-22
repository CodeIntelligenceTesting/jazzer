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

import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toList;

import com.code_intelligence.jazzer.driver.Driver;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.AbstractMap.SimpleEntry;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

/**
 * Entrypoint for Jazzer to run in a user-controlled JVM rather than the JVM started by the native
 * Jazzer launcher.
 *
 * <p>Arguments to Jazzer are passed as command-line arguments or {@code jazzer.*} system
 * properties. For example, setting the property {@code jazzer.target_class} to
 * {@code com.example.FuzzTest} is equivalent to passing the argument
 * {@code --target_class=com.example.FuzzTest}.
 *
 * <p>Arguments to libFuzzer are passed as command-line arguments.
 */
public class Jazzer {
  public static void main(String[] args) throws IOException {
    start(Stream.concat(Stream.of(prepareArgv0()), Arrays.stream(args)).collect(toList()));
  }

  // Accessed by jazzer_main.cpp.
  @SuppressWarnings("unused")
  private static void main(byte[][] nativeArgs) throws IOException {
    start(Arrays.stream(nativeArgs)
              .map(bytes -> new String(bytes, StandardCharsets.UTF_8))
              .collect(toList()));
  }

  private static void start(List<String> args) throws IOException {
    parseJazzerArgsToProperties(args);
    System.exit(Driver.start(args));
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

  private static String prepareArgv0() throws IOException {
    char shellQuote = isPosix() ? '\'' : '"';
    String launcherTemplate = isPosix() ? "#!/usr/bin/env sh\n%s $@\n" : "@echo off\r\n%s %%*\r\n";
    String launcherExtension = isPosix() ? ".sh" : ".bat";
    FileAttribute<?>[] launcherScriptAttributes = isPosix()
        ? new FileAttribute[] {PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rwx------"))}
        : new FileAttribute[] {};
    // Create a wrapper script that faithfully recreates the current JVM. By using this script as
    // libFuzzer's argv[0], libFuzzer modes that rely on subprocesses can work with the Java driver.
    String command = Stream
                         .concat(Stream.of(javaBinary().toString()), javaBinaryArgs())
                         // Escape individual arguments for the shell.
                         .map(str -> shellQuote + str + shellQuote)
                         .collect(joining(" "));
    String launcherContent = String.format(launcherTemplate, command);
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
        Stream.of("-cp", System.getProperty("java.class.path"), Jazzer.class.getName()));
  }

  private static boolean isPosix() {
    return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
  }
}
