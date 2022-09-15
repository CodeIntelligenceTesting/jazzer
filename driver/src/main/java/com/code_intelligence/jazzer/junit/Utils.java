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
   * Returns the resource path of the seed corpus directory, which is either absolute or relative to
   * {@code testClass}.
   */
  static String seedCorpusResourcePath(Class<?> testClass, FuzzTest annotation) {
    if (annotation.seedCorpus().isEmpty()) {
      return testClass.getSimpleName() + "SeedCorpus";
    }
    return annotation.seedCorpus();
  }

  /**
   * Returns the file system path of the seed corpus directory in the source tree, if it exists.
   */
  static Optional<Path> seedCorpusSourcePath(
      Class<?> testClass, FuzzTest annotation, Path baseDir) {
    String seedCorpusResourcePath = Utils.seedCorpusResourcePath(testClass, annotation);
    // Make the seed corpus resource path absolute.
    if (!seedCorpusResourcePath.startsWith("/")) {
      String seedCorpusPackage = testClass.getPackage().getName().replace('.', '/');
      seedCorpusResourcePath = "/" + seedCorpusPackage + "/" + seedCorpusResourcePath;
    }

    // Following the Maven directory layout, we look up the seed corpus under src/test/resources.
    // This should be correct also for multi-module projects as JUnit is usually launched in the
    // current module's root directory.
    Path sourceSeedCorpusPath = baseDir.resolve(
        ("src/test/resources" + seedCorpusResourcePath).replace('/', File.separatorChar));
    if (Files.isDirectory(sourceSeedCorpusPath)) {
      return Optional.of(sourceSeedCorpusPath);
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
}
