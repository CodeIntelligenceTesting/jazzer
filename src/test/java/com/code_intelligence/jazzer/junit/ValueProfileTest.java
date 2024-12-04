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
import static org.junit.platform.testkit.engine.EventType.STARTED;
import static org.junit.platform.testkit.engine.TestExecutionResultConditions.cause;
import static org.junit.platform.testkit.engine.TestExecutionResultConditions.instanceOf;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
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

public class ValueProfileTest {
  private static final boolean VALUE_PROFILE_ENABLED =
      "True".equals(System.getenv("JAZZER_VALUE_PROFILE"));

  private static final String ENGINE = "engine:junit-jupiter";
  private static final String CLAZZ = "class:com.example.ValueProfileFuzzTest";
  private static final String VALUE_PROFILE_FUZZ = "test-template:valueProfileFuzz([B)";
  private static final String INVOCATION = "test-template-invocation:#";

  @Rule public TemporaryFolder temp = new TemporaryFolder();
  Path baseDir;
  Path inputsDirectories;

  @Before
  public void setup() throws IOException {
    baseDir = temp.getRoot().toPath();
    // Create a fake test resource directory structure with an input directory to verify that
    // Jazzer uses it and emits a crash file into it.
    inputsDirectories =
        baseDir.resolve(
            Paths.get(
                "src",
                "test",
                "resources",
                "com",
                "example",
                "ValueProfileFuzzTestInputs",
                "valueProfileFuzz"));
    Files.createDirectories(inputsDirectories);
  }

  private EngineExecutionResults executeTests() {
    return EngineTestKit.engine("junit-jupiter")
        .selectors(selectClass("com.example.ValueProfileFuzzTest"))
        .configurationParameter(
            "jazzer.instrument", "com.other.package.**,com.example.**,com.yet.another.package.*")
        .configurationParameter("jazzer.valueprofile", System.getenv("JAZZER_VALUE_PROFILE"))
        .configurationParameter("jazzer.internal.basedir", baseDir.toAbsolutePath().toString())
        .execute();
  }

  @Test
  public void valueProfileEnabled() throws IOException {
    assumeTrue(VALUE_PROFILE_ENABLED);

    EngineExecutionResults results = executeTests();

    results
        .containerEvents()
        .assertEventsMatchExactly(
            event(type(STARTED), container(ENGINE)),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ))),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ))),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ)),
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
                test(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ))),
            event(
                type(STARTED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ, INVOCATION + 1)),
                displayName("<empty input>")),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ, INVOCATION + 1)),
                displayName("<empty input>"),
                finishedSuccessfully()),
            event(
                type(DYNAMIC_TEST_REGISTERED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ))),
            event(
                type(STARTED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ, INVOCATION + 2)),
                displayName("empty_seed")),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ, INVOCATION + 2)),
                displayName("empty_seed"),
                finishedSuccessfully()),
            event(
                type(DYNAMIC_TEST_REGISTERED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ))),
            event(
                type(STARTED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ, INVOCATION + 3)),
                displayName("Fuzzing...")),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ, INVOCATION + 3)),
                displayName("Fuzzing..."),
                finishedWithFailure(
                    instanceOf(FuzzTestFindingException.class),
                    cause(instanceOf(FuzzerSecurityIssueMedium.class)))));

    // Should crash on the exact input "Jazzer", with the crash emitted into the seed corpus.
    try (Stream<Path> crashFiles =
        Files.list(baseDir).filter(path -> path.getFileName().toString().startsWith("crash-"))) {
      assertThat(crashFiles).isEmpty();
    }
    try (Stream<Path> seeds = Files.list(inputsDirectories)) {
      assertThat(seeds)
          .containsExactly(
              inputsDirectories.resolve("crash-131db69c7fadc408fe5031079dad3a441df09aff"));
    }
    assertThat(
            Files.readAllBytes(
                inputsDirectories.resolve("crash-131db69c7fadc408fe5031079dad3a441df09aff")))
        .isEqualTo("Jazzer".getBytes(StandardCharsets.UTF_8));

    // Verify that the engine created the generated corpus directory and emitted inputs into it.
    Path generatedCorpus =
        baseDir.resolve(Paths.get(".cifuzz-corpus", "com.example.ValueProfileFuzzTest"));
    assertThat(Files.isDirectory(generatedCorpus)).isTrue();
    try (Stream<Path> entries = Files.list(generatedCorpus)) {
      assertThat(entries).isNotEmpty();
    }
  }

  @Test
  public void valueProfileDisabled() throws IOException {
    assumeFalse(VALUE_PROFILE_ENABLED);

    EngineExecutionResults results = executeTests();

    results
        .containerEvents()
        .assertEventsMatchExactly(
            event(type(STARTED), container(ENGINE)),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ))),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ))),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ)),
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
                test(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ))),
            event(
                type(STARTED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ, INVOCATION + 1)),
                displayName("<empty input>")),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ, INVOCATION + 1)),
                displayName("<empty input>"),
                finishedSuccessfully()),
            event(
                type(DYNAMIC_TEST_REGISTERED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ))),
            event(
                type(STARTED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ, INVOCATION + 2)),
                displayName("empty_seed")),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ, INVOCATION + 2)),
                displayName("empty_seed"),
                finishedSuccessfully()),
            event(
                type(DYNAMIC_TEST_REGISTERED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ))),
            event(
                type(STARTED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ, INVOCATION + 3)),
                displayName("Fuzzing...")),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, VALUE_PROFILE_FUZZ, INVOCATION + 3)),
                displayName("Fuzzing..."),
                finishedSuccessfully()));

    // No crash means no crashing input is emitted anywhere.
    try (Stream<Path> crashFiles =
        Files.list(baseDir).filter(path -> path.getFileName().toString().startsWith("crash-"))) {
      assertThat(crashFiles).isEmpty();
    }
    try (Stream<Path> seeds = Files.list(inputsDirectories)) {
      assertThat(seeds).isEmpty();
    }

    // Verify that the engine created the generated corpus directory and emitted inputs into it.
    Path generatedCorpus =
        baseDir.resolve(Paths.get(".cifuzz-corpus", "com.example.ValueProfileFuzzTest"));
    assertThat(Files.isDirectory(generatedCorpus)).isTrue();
    try (Stream<Path> entries = Files.list(generatedCorpus)) {
      assertThat(entries).isNotEmpty();
    }
  }
}
