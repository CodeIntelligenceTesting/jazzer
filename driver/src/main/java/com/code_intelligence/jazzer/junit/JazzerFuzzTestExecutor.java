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

import com.code_intelligence.jazzer.driver.FuzzTargetRunner;
import com.code_intelligence.jazzer.junit.JazzerTestEngine.JazzerFuzzTestDescriptor;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.platform.commons.support.AnnotationSupport;
import org.junit.platform.engine.ExecutionRequest;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.reporting.ReportEntry;

public class JazzerFuzzTestExecutor {
  private static final AtomicBoolean hasExecutedOnce = new AtomicBoolean();

  private final ExecutionRequest request;
  private final JazzerFuzzTestDescriptor fuzzTestDescriptor;
  private final Path baseDir;

  public JazzerFuzzTestExecutor(
      ExecutionRequest request, JazzerFuzzTestDescriptor fuzzTestDescriptor, Path baseDir) {
    this.request = request;
    this.fuzzTestDescriptor = fuzzTestDescriptor;
    this.baseDir = baseDir;
  }

  public TestExecutionResult execute() throws IOException, URISyntaxException {
    if (!hasExecutedOnce.compareAndSet(false, true)) {
      throw new IllegalStateException(
          "Only a single fuzz test can be executed by JazzerFuzzTestExecutor per test run");
    }

    final Method fuzzTestMethod = fuzzTestDescriptor.getMethod();
    final Class<?> fuzzTestClass = fuzzTestMethod.getDeclaringClass();

    ArrayList<String> libFuzzerArgs = new ArrayList<>();
    libFuzzerArgs.add("fake_argv0");

    // Store the generated corpus in a per-class directory under the project root, just like cifuzz:
    // https://github.com/CodeIntelligenceTesting/cifuzz/blob/bf410dcfbafbae2a73cf6c5fbed031cdfe234f2f/internal/cmd/run/run.go#L381
    // The path is specified relative to the current working directory, which with JUnit is the
    // project directory.
    Path generatedCorpusDir = baseDir.resolve(Utils.generatedCorpusPath(fuzzTestClass));
    Files.createDirectories(generatedCorpusDir);
    libFuzzerArgs.add(generatedCorpusDir.toAbsolutePath().toString());

    // If the default or configured seed corpus directory for the fuzz test exists as a regular
    // directory on disk (i.e., the test is not run from a JAR), use it as a seeds directory for
    // libFuzzer and also emit findings into it so that the regression test can be used to debug
    // them.
    FuzzTest fuzzTest = AnnotationSupport.findAnnotation(fuzzTestMethod, FuzzTest.class).get();
    String seedCorpusResourcePath = fuzzTest.seedCorpus().isEmpty()
        ? Utils.defaultSeedCorpusPath(fuzzTestClass)
        : fuzzTest.seedCorpus();
    URL seedCorpusUrl = fuzzTestClass.getResource(seedCorpusResourcePath);
    if (seedCorpusUrl == null) {
      if (fuzzTest.seedCorpus().isEmpty()) {
        // Situation: The user may not be aware of the seed corpus feature.
        String message = String.format(
            "Collecting crashing inputs in the project root directory.\nIf you want to keep them organized by "
                + "fuzz test and automatically run them as regression tests with JUnit Jupiter, create a "
                + "test resource directory called '%s' in package '%s' and move the files there.",
            seedCorpusResourcePath, fuzzTestClass.getPackage().getName());
        request.getEngineExecutionListener().reportingEntryPublished(
            fuzzTestDescriptor, ReportEntry.from("seed corpus", message));
      } else {
        // Situation: The user explicitly configured a seed corpus, but it couldn't be found.
        throw new FileNotFoundException(
            String.format("Failed to find seed corpus at '%s' relative to '%s'",
                fuzzTest.seedCorpus(), fuzzTestClass));
      }
    } else if ("file".equals(seedCorpusUrl.getProtocol())) {
      // From the second positional argument on, files and directories are used as seeds but not
      // modified. Using seedCorpusUrl.getFile() fails on Windows.
      libFuzzerArgs.add(Paths.get(seedCorpusUrl.toURI()).toString());
      // We try to find the source tree representation of the seed corpus directory and emit
      // findings into it.
      findSeedCorpusDirectoryInSourceTree().ifPresent(
          (path)
              -> libFuzzerArgs.add(
                  String.format("-artifact_prefix=%s%c", path, File.separatorChar)));
    } else {
      // We can't directly use the seed corpus from resources as it's packaged into a JAR. Instead,
      // try to get the path to the seed corpus in the source tree.
      Optional<Path> seedCorpusSourceDirectory = findSeedCorpusDirectoryInSourceTree();
      if (seedCorpusSourceDirectory.isPresent()) {
        libFuzzerArgs.add(seedCorpusSourceDirectory.get().toString());
        // We try to find the source tree representation of the seed corpus directory and emit
        // findings into it.
        libFuzzerArgs.add(String.format(
            "-artifact_prefix=%s%c", seedCorpusSourceDirectory.get(), File.separatorChar));
      } else {
        request.getEngineExecutionListener().reportingEntryPublished(fuzzTestDescriptor,
            ReportEntry.from("seed corpus",
                "When running Jazzer fuzz tests from a JAR rather than class files, the seed corpus isn't used unless it is located under src/test/resources/..."));
      }
    }

    libFuzzerArgs.add("-max_total_time=" + durationStringToSeconds(fuzzTest.maxDuration()));
    // Disable libFuzzer's out of memory detection: It is only useful for native library fuzzing,
    // which we don't support without our native driver, and leads to false positives where it picks
    // up IntelliJ's memory usage.
    libFuzzerArgs.add("-rss_limit_mb=0");
    if (request.getConfigurationParameters().getBoolean("jazzer.valueprofile").orElse(false)) {
      libFuzzerArgs.add("-use_value_profile=1");
    }

    System.setProperty("jazzer.target_class", fuzzTestClass.getName());
    System.setProperty("jazzer.target_method", fuzzTestMethod.getName());
    AgentConfigurator.forFuzzing(request, fuzzTestClass);

    AtomicReference<Throwable> atomicFinding = new AtomicReference<>();
    FuzzTargetRunner.registerFindingHandler(t -> {
      atomicFinding.set(t);
      return false;
    });
    int exitCode = FuzzTargetRunner.startLibFuzzer(libFuzzerArgs);
    Throwable finding = atomicFinding.get();
    if (finding != null) {
      return TestExecutionResult.failed(finding);
    } else if (exitCode != 0) {
      return TestExecutionResult.failed(
          new JazzerTestEngine.JazzerSetupError("libFuzzer exited with exit code " + exitCode));
    } else {
      return TestExecutionResult.successful();
    }
  }

  private static long durationStringToSeconds(String duration) {
    // Convert the string to ISO 8601 (https://en.wikipedia.org/wiki/ISO_8601#Durations). We do not
    // allow for duration
    // units longer than hours, so we can always prepend PT.
    String isoDuration = "PT" + duration.replace("min", "m").replace(" ", "");
    return Duration.parse(isoDuration).getSeconds();
  }

  private Optional<Path> findSeedCorpusDirectoryInSourceTree() {
    FuzzTest fuzzTest =
        AnnotationSupport.findAnnotation(fuzzTestDescriptor.getMethod(), FuzzTest.class).get();
    String seedCorpusResourcePath = fuzzTest.seedCorpus().isEmpty()
        ? Utils.defaultSeedCorpusPath(fuzzTestDescriptor.getMethod().getDeclaringClass())
        : fuzzTest.seedCorpus();
    // Make the seed corpus resource path absolute.
    if (!seedCorpusResourcePath.startsWith("/")) {
      String seedCorpusPackage =
          fuzzTestDescriptor.getMethod().getDeclaringClass().getPackage().getName().replace(
              '.', '/');
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
}
