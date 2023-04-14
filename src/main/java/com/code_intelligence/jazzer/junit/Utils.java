// Copyright 2022 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.junit;

import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.ExtensionContext;

class Utils {
  /**
   * Returns the resource path of the inputs directory for a given test class and method. The path
   * will have the form
   * {@code <class name>Inputs/<method name>}
   */
  static String inputsDirectoryResourcePath(Class<?> testClass, Method testMethod) {
    return testClass.getSimpleName() + "Inputs"
        + "/" + testMethod.getName();
  }

  /**
   * Returns the file system path of the inputs corpus directory in the source tree, if it exists.
   * The directory is created if it does not exist, but the test resource directory itself exists.
   */
  static Optional<Path> inputsDirectorySourcePath(
      Class<?> testClass, Method testMethod, Path baseDir) {
    String inputsResourcePath = Utils.inputsDirectoryResourcePath(testClass, testMethod);
    // Make the inputs resource path absolute.
    if (!inputsResourcePath.startsWith("/")) {
      String inputsPackage = testClass.getPackage().getName().replace('.', '/');
      inputsResourcePath = "/" + inputsPackage + "/" + inputsResourcePath;
    }

    // Following the Maven directory layout, we look up the inputs directory under
    // src/test/resources. This should be correct also for multi-module projects as JUnit is usually
    // launched in the current module's root directory.
    Path testResourcesDirectory = baseDir.resolve("src").resolve("test").resolve("resources");
    Path sourceInputsDirectory = testResourcesDirectory;
    for (String segment : inputsResourcePath.split("/")) {
      sourceInputsDirectory = sourceInputsDirectory.resolve(segment);
    }
    if (Files.isDirectory(sourceInputsDirectory)) {
      return Optional.of(sourceInputsDirectory);
    }
    // If we can at least find the test resource directory, create the inputs directory.
    if (!Files.isDirectory(testResourcesDirectory)) {
      return Optional.empty();
    }
    try {
      return Optional.of(Files.createDirectories(sourceInputsDirectory));
    } catch (Exception e) {
      return Optional.empty();
    }
  }

  static Path generatedCorpusPath(Class<?> testClass, Method testMethod) {
    return Paths.get(".cifuzz-corpus", testClass.getName(), testMethod.getName());
  }

  static String defaultInstrumentationFilter(Class<?> testClass) {
    // This is an extremely rough "implementation" of the public suffix list algorithm
    // (https://publicsuffix.org/): It tries to guess the shortest prefix of the package name that
    // isn't public. It doesn't use the actual list, but instead assumes that every root segment as
    // well as "com.github" are public. Examples:
    // - com.example.Test --> com.example.**
    // - com.example.foobar.Test --> com.example.**
    // - com.github.someones.repo.Test --> com.github.someones.**
    String packageName = testClass.getPackage().getName();
    String[] packageSegments = packageName.split("\\.");
    int numSegments = 2;
    if (packageSegments.length > 2 && packageSegments[0].equals("com")
        && packageSegments[1].equals("github")) {
      numSegments = 3;
    }
    return Stream.concat(Arrays.stream(packageSegments).limit(numSegments), Stream.of("**"))
        .collect(Collectors.joining("."));
  }

  private static final Pattern COVERAGE_AGENT_ARG =
      Pattern.compile("-javaagent:.*(?:intellij-coverage-agent|jacoco).*");
  static boolean isCoverageAgentPresent() {
    return ManagementFactory.getRuntimeMXBean().getInputArguments().stream().anyMatch(
        s -> COVERAGE_AGENT_ARG.matcher(s).matches());
  }

  private static final boolean IS_FUZZING_ENV =
      System.getenv("JAZZER_FUZZ") != null && !System.getenv("JAZZER_FUZZ").isEmpty();
  static boolean isFuzzing(ExtensionContext extensionContext) {
    return IS_FUZZING_ENV || runFromCommandLine(extensionContext);
  }

  static boolean runFromCommandLine(ExtensionContext extensionContext) {
    return extensionContext.getConfigurationParameter("jazzer.internal.commandLine")
        .map(Boolean::parseBoolean)
        .orElse(false);
  }

  /**
   * Returns true if and only if the value is equal to "true", "1", or "yes" case-insensitively.
   */
  static boolean permissivelyParseBoolean(String value) {
    return value.equalsIgnoreCase("true") || value.equals("1") || value.equalsIgnoreCase("yes");
  }

  /**
   * Convert the string to ISO 8601 (https://en.wikipedia.org/wiki/ISO_8601#Durations).
   * We do not allow for duration units longer than hours, so we can always prepend PT.
   */
  static long durationStringToSeconds(String duration) {
    String isoDuration =
        "PT" + duration.replace("sec", "s").replace("min", "m").replace("hr", "h").replace(" ", "");
    return Duration.parse(isoDuration).getSeconds();
  }
}
