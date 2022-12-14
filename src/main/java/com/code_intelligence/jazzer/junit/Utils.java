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

import java.io.File;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class Utils {
  /**
   * Returns the resource path of the inputs directory, which is either absolute or relative to
   * {@code testClass}.
   */
  static String inputsDirectoryResourcePath(Class<?> testClass) {
    return testClass.getSimpleName() + "Inputs";
  }

  /**
   * Returns the file system path of the inputs corpus directory in the source tree, if it exists.
   */
  static Optional<Path> inputsDirectorySourcePath(Class<?> testClass, Path baseDir) {
    String inputsResourcePath = Utils.inputsDirectoryResourcePath(testClass);
    // Make the inputs resource path absolute.
    if (!inputsResourcePath.startsWith("/")) {
      String inputsPackage = testClass.getPackage().getName().replace('.', '/');
      inputsResourcePath = "/" + inputsPackage + "/" + inputsResourcePath;
    }

    // Following the Maven directory layout, we look up the inputs directory under
    // src/test/resources. This should be correct also for multi-module projects as JUnit is usually
    // launched in the current module's root directory.
    Path sourceInputsDirectory = baseDir.resolve(
        ("src/test/resources" + inputsResourcePath).replace('/', File.separatorChar));
    if (Files.isDirectory(sourceInputsDirectory)) {
      return Optional.of(sourceInputsDirectory);
    } else {
      return Optional.empty();
    }
  }

  static Path generatedCorpusPath(Class<?> testClass) {
    return Paths.get(".cifuzz-corpus", testClass.getName());
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

  private static final boolean IS_FUZZING =
      System.getenv("JAZZER_FUZZ") != null && !System.getenv("JAZZER_FUZZ").isEmpty();
  static boolean isFuzzing() {
    return IS_FUZZING;
  }

  /**
   * Returns true if and only if the value is equal to "true", "1", or "yes" case-insensitively.
   */
  static boolean permissivelyParseBoolean(String value) {
    return value.equalsIgnoreCase("true") || value.equals("1") || value.equalsIgnoreCase("yes");
  }
}
