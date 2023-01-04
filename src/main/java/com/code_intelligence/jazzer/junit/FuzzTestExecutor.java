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

import static com.code_intelligence.jazzer.junit.Utils.generatedCorpusPath;
import static com.code_intelligence.jazzer.junit.Utils.inputsDirectoryResourcePath;
import static com.code_intelligence.jazzer.junit.Utils.inputsDirectorySourcePath;
import static com.code_intelligence.jazzer.utils.Utils.getReadableDescriptor;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.driver.FuzzTargetRunner;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.extension.ExtensionContext;

class FuzzTestExecutor {
  private static final AtomicBoolean hasBeenPrepared = new AtomicBoolean();

  private final List<String> libFuzzerArgs;

  private FuzzTestExecutor(List<String> libFuzzerArgs) {
    this.libFuzzerArgs = libFuzzerArgs;
  }

  public static FuzzTestExecutor prepare(ExtensionContext context, String maxDuration)
      throws IOException {
    if (!hasBeenPrepared.compareAndSet(false, true)) {
      throw new IllegalStateException(
          "JazzerFuzzTestExecutor#prepare can only be called once per test run");
    }

    Path baseDir =
        Paths.get(context.getConfigurationParameter("jazzer.internal.basedir").orElse(""))
            .toAbsolutePath();

    final Method fuzzTestMethod = context.getRequiredTestMethod();
    final Class<?> fuzzTestClass = context.getRequiredTestClass();

    ArrayList<String> libFuzzerArgs = new ArrayList<>();
    libFuzzerArgs.add("fake_argv0");

    // Store the generated corpus in a per-class directory under the project root, just like cifuzz:
    // https://github.com/CodeIntelligenceTesting/cifuzz/blob/bf410dcfbafbae2a73cf6c5fbed031cdfe234f2f/internal/cmd/run/run.go#L381
    // The path is specified relative to the current working directory, which with JUnit is the
    // project directory.
    Path generatedCorpusDir = baseDir.resolve(generatedCorpusPath(fuzzTestClass));
    Files.createDirectories(generatedCorpusDir);
    libFuzzerArgs.add(generatedCorpusDir.toAbsolutePath().toString());

    // We can only emit findings into the source tree version of the inputs directory, not e.g. the
    // copy under Maven's target directory. If it doesn't exist, collect the inputs in the current
    // working directory, which is usually the project's source root.
    Optional<Path> findingsDirectory = inputsDirectorySourcePath(fuzzTestClass, baseDir);
    if (!findingsDirectory.isPresent()) {
      context.publishReportEntry(String.format(
          "Collecting crashing inputs in the project root directory.\nIf you want to keep them "
              + "organized by fuzz test and automatically run them as regression tests with "
              + "JUnit Jupiter, create a test resource directory called '%s' in package '%s' "
              + "and move the files there.",
          inputsDirectoryResourcePath(fuzzTestClass), fuzzTestClass.getPackage().getName()));
    }

    // We prefer the inputs directory on the classpath, if it exists, as that is more reliable than
    // heuristically looking into the source tree based on the current working directory.
    Optional<Path> inputsDirectory;
    URL inputsDirectoryUrl = fuzzTestClass.getResource(inputsDirectoryResourcePath(fuzzTestClass));
    if (inputsDirectoryUrl != null && "file".equals(inputsDirectoryUrl.getProtocol())) {
      // The inputs directory is a regular directory on disk (i.e., the test is not run from a
      // JAR).
      try {
        // Using inputsDirectoryUrl.getFile() fails on Windows.
        inputsDirectory = Optional.of(Paths.get(inputsDirectoryUrl.toURI()));
      } catch (URISyntaxException e) {
        throw new RuntimeException(e);
      }
    } else {
      if (inputsDirectoryUrl != null && !findingsDirectory.isPresent()) {
        context.publishReportEntry(
            "When running Jazzer fuzz tests from a JAR rather than class files, the inputs "
            + "directory isn't used unless it is located under src/test/resources/...");
      }
      inputsDirectory = findingsDirectory;
    }

    // From the second positional argument on, files and directories are used as seeds but not
    // modified.
    inputsDirectory.ifPresent(dir -> libFuzzerArgs.add(dir.toAbsolutePath().toString()));
    libFuzzerArgs.add(String.format("-artifact_prefix=%s%c",
        findingsDirectory.orElse(baseDir).toAbsolutePath(), File.separatorChar));

    libFuzzerArgs.add("-max_total_time=" + durationStringToSeconds(maxDuration));
    // Disable libFuzzer's out of memory detection: It is only useful for native library fuzzing,
    // which we don't support without our native driver, and leads to false positives where it picks
    // up IntelliJ's memory usage.
    libFuzzerArgs.add("-rss_limit_mb=0");
    if (Utils.permissivelyParseBoolean(
            context.getConfigurationParameter("jazzer.valueprofile").orElse("false"))) {
      libFuzzerArgs.add("-use_value_profile=1");
    }

    if (fuzzTestMethod.getParameterCount() == 0) {
      throw new IllegalArgumentException(
          "Methods annotated with @FuzzTest must take at least one parameter");
    }
    if (fuzzTestMethod.getParameterCount() == 1
        && (fuzzTestMethod.getParameterTypes()[0] == byte[].class
            || fuzzTestMethod.getParameterTypes()[0] == FuzzedDataProvider.class)) {
      System.setProperty("jazzer.target_class", fuzzTestClass.getName());
      System.setProperty("jazzer.target_method", fuzzTestMethod.getName());
    } else {
      System.setProperty("jazzer.autofuzz",
          String.format("%s::%s%s", fuzzTestClass.getName(), fuzzTestMethod.getName(),
              getReadableDescriptor(fuzzTestMethod)));
    }

    return new FuzzTestExecutor(libFuzzerArgs);
  }

  public Optional<Throwable> execute() {
    AtomicReference<Throwable> atomicFinding = new AtomicReference<>();
    FuzzTargetRunner.registerFindingHandler(t -> {
      atomicFinding.set(t);
      return false;
    });
    int exitCode = FuzzTargetRunner.startLibFuzzer(libFuzzerArgs);
    Throwable finding = atomicFinding.get();
    if (finding != null) {
      return Optional.of(finding);
    } else if (exitCode != 0) {
      return Optional.of(new IllegalStateException("Jazzer exited with exit code " + exitCode));
    } else {
      return Optional.empty();
    }
  }

  static long durationStringToSeconds(String duration) {
    // Convert the string to ISO 8601 (https://en.wikipedia.org/wiki/ISO_8601#Durations). We do not
    // allow for duration units longer than hours, so we can always prepend PT.
    String isoDuration =
        "PT" + duration.replace("sec", "s").replace("min", "m").replace("hr", "h").replace(" ", "");
    return Duration.parse(isoDuration).getSeconds();
  }
}
