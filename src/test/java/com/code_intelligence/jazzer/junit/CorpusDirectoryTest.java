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

package com.code_intelligence.jazzer.junit;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;
import static org.junit.platform.testkit.engine.EventConditions.container;
import static org.junit.platform.testkit.engine.EventConditions.displayName;
import static org.junit.platform.testkit.engine.EventConditions.event;
import static org.junit.platform.testkit.engine.EventConditions.finishedSuccessfully;
import static org.junit.platform.testkit.engine.EventConditions.finishedWithFailure;
import static org.junit.platform.testkit.engine.EventConditions.test;
import static org.junit.platform.testkit.engine.EventConditions.type;
import static org.junit.platform.testkit.engine.EventConditions.uniqueIdSubstrings;
import static org.junit.platform.testkit.engine.EventType.DYNAMIC_TEST_REGISTERED;
import static org.junit.platform.testkit.engine.EventType.FINISHED;
import static org.junit.platform.testkit.engine.EventType.REPORTING_ENTRY_PUBLISHED;
import static org.junit.platform.testkit.engine.EventType.STARTED;
import static org.junit.platform.testkit.engine.TestExecutionResultConditions.cause;
import static org.junit.platform.testkit.engine.TestExecutionResultConditions.instanceOf;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.platform.testkit.engine.EngineExecutionResults;
import org.junit.platform.testkit.engine.EngineTestKit;
import org.junit.rules.TemporaryFolder;

public class CorpusDirectoryTest {
  private static final String ENGINE = "engine:junit-jupiter";
  private static final String CLAZZ = "class:com.example.CorpusDirectoryFuzzTest";
  private static final String INPUTS_FUZZ =
      "test-template:corpusDirectoryFuzz(com.code_intelligence.jazzer.api.FuzzedDataProvider)";
  private static final String INVOCATION = "test-template-invocation:#";

  @Rule public TemporaryFolder temp = new TemporaryFolder();
  Path baseDir;

  @Before
  public void setup() {
    baseDir = temp.getRoot().toPath();
  }

  @Test
  public void fuzzingEnabled() throws IOException {
    assumeFalse(System.getenv("JAZZER_FUZZ").isEmpty());

    // Create a fake test resource directory structure with an inputs directory to verify that
    // Jazzer uses it and emits a crash file into it.
    Path artifactsDirectory =
        baseDir.resolve(
            Paths.get(
                "src",
                "test",
                "resources",
                "com",
                "example",
                "CorpusDirectoryFuzzTestInputs",
                "corpusDirectoryFuzz"));
    Files.createDirectories(artifactsDirectory);

    // An explicitly stated corpus directory should be used to save new corpus entries.
    Path explicitGeneratedCorpus = baseDir.resolve(Paths.get("corpus"));
    Files.createDirectories(explicitGeneratedCorpus);

    // The default generated corpus directory should only be used if no explicit corpus directory
    // is given.
    Path defaultGeneratedCorpus =
        baseDir.resolve(
            Paths.get(
                ".cifuzz-corpus", "com.example.CorpusDirectoryFuzzTest", "corpusDirectoryFuzz"));

    EngineExecutionResults results =
        EngineTestKit.engine("junit-jupiter")
            .selectors(selectClass("com.example.CorpusDirectoryFuzzTest"))
            .configurationParameter("jazzer.internal.basedir", baseDir.toAbsolutePath().toString())
            // Add corpus directory as initial libFuzzer parameter.
            .configurationParameter("jazzer.internal.arg.0", "fake_test_argv0")
            .configurationParameter(
                "jazzer.internal.arg.1", explicitGeneratedCorpus.toAbsolutePath().toString())
            .execute();

    results
        .containerEvents()
        .assertEventsMatchExactly(
            event(type(STARTED), container(ENGINE)),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ))),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ))),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ)),
                finishedSuccessfully()),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ)),
                finishedSuccessfully()),
            event(type(FINISHED), container(ENGINE), finishedSuccessfully()));

    results
        .testEvents()
        .assertEventsMatchExactly(
            event(
                type(DYNAMIC_TEST_REGISTERED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ))),
            event(
                type(STARTED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ, INVOCATION + 1))),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ, INVOCATION + 1)),
                displayName("<empty input>"),
                finishedSuccessfully()),
            event(
                type(DYNAMIC_TEST_REGISTERED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ))),
            event(
                type(STARTED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ, INVOCATION + 2))),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ, INVOCATION + 2)),
                displayName("seed"),
                finishedSuccessfully()),
            event(
                type(DYNAMIC_TEST_REGISTERED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ))),
            event(
                type(STARTED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ, INVOCATION + 3)),
                displayName("Fuzzing...")),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ, INVOCATION + 3)),
                displayName("Fuzzing..."),
                finishedWithFailure(
                    instanceOf(FuzzTestFindingException.class),
                    cause(instanceOf(FuzzerSecurityIssueMedium.class)))));

    // Crash file should be emitted into the artifacts directory and not into corpus directory.
    assertCrashFileExistsIn(artifactsDirectory);
    assertNoCrashFileExistsIn(baseDir);
    assertNoCrashFileExistsIn(explicitGeneratedCorpus);
    // Default generated corpus directory isn't used and thus should not have been created.
    assertThat(Files.notExists(defaultGeneratedCorpus)).isTrue();

    // Verify that corpus files are written to given corpus directory and not generated one.
    assertThat(Files.list(explicitGeneratedCorpus)).isNotEmpty();
  }

  @Test
  public void fuzzingDisabled() throws IOException {
    assumeTrue(System.getenv("JAZZER_FUZZ").isEmpty());

    Path corpusDirectory = baseDir.resolve(Paths.get("corpus"));
    Files.createDirectories(corpusDirectory);
    Files.createFile(corpusDirectory.resolve("corpus_entry"));

    EngineExecutionResults results =
        EngineTestKit.engine("junit-jupiter")
            .selectors(selectClass("com.example.CorpusDirectoryFuzzTest"))
            .configurationParameter("jazzer.internal.basedir", baseDir.toAbsolutePath().toString())
            // Add corpus directory as initial libFuzzer parameter.
            .configurationParameter("jazzer.internal.arg.0", "fake_test_argv0")
            .configurationParameter(
                "jazzer.internal.arg.1", corpusDirectory.toAbsolutePath().toString())
            .execute();

    results
        .containerEvents()
        .assertEventsMatchExactly(
            event(type(STARTED), container(ENGINE)),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ))),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ))),
            event(
                type(REPORTING_ENTRY_PUBLISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ))),
            event(type(FINISHED), container(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ))),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ)),
                finishedSuccessfully()),
            event(type(FINISHED), container(ENGINE), finishedSuccessfully()));

    // Verify that corpus_entry is not picked up and corpus directory is ignored in regression mode.
    results
        .testEvents()
        .assertEventsMatchExactly(
            event(
                type(DYNAMIC_TEST_REGISTERED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ))),
            event(
                type(STARTED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ, INVOCATION + 1))),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ, INVOCATION + 1)),
                displayName("<empty input>"),
                finishedSuccessfully()),
            event(
                type(DYNAMIC_TEST_REGISTERED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ))),
            event(
                type(STARTED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ, INVOCATION + 2))),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ, INVOCATION + 2)),
                displayName("seed"),
                finishedSuccessfully()));
  }

  private static void assertCrashFileExistsIn(Path artifactsDirectory) throws IOException {
    try (Stream<Path> crashFiles =
        Files.list(artifactsDirectory)
            .filter(path -> path.getFileName().toString().startsWith("crash-"))) {
      assertThat(crashFiles).isNotEmpty();
    }
  }

  private static void assertNoCrashFileExistsIn(Path generatedCorpus) throws IOException {
    try (Stream<Path> crashFiles =
        Files.list(generatedCorpus)
            .filter(path -> path.getFileName().toString().startsWith("crash-"))) {
      assertThat(crashFiles).isEmpty();
    }
  }
}
