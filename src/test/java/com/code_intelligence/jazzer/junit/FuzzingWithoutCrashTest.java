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
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectMethod;
import static org.junit.platform.testkit.engine.EventConditions.container;
import static org.junit.platform.testkit.engine.EventConditions.displayName;
import static org.junit.platform.testkit.engine.EventConditions.event;
import static org.junit.platform.testkit.engine.EventConditions.finishedSuccessfully;
import static org.junit.platform.testkit.engine.EventConditions.test;
import static org.junit.platform.testkit.engine.EventConditions.type;
import static org.junit.platform.testkit.engine.EventConditions.uniqueIdSubstrings;
import static org.junit.platform.testkit.engine.EventType.DYNAMIC_TEST_REGISTERED;
import static org.junit.platform.testkit.engine.EventType.FINISHED;
import static org.junit.platform.testkit.engine.EventType.REPORTING_ENTRY_PUBLISHED;
import static org.junit.platform.testkit.engine.EventType.STARTED;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.assertj.core.api.Condition;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.platform.testkit.engine.EngineExecutionResults;
import org.junit.platform.testkit.engine.EngineTestKit;
import org.junit.rules.TemporaryFolder;

public class FuzzingWithoutCrashTest {
  private static final String ENGINE = "engine:junit-jupiter";
  private static final String CLAZZ = "class:com.example.ValidFuzzTests";
  private static final String NO_CRASH_FUZZ = "test-template:noCrashFuzz([B)";
  private static final String INVOCATION = "test-template-invocation:#";
  @Rule public TemporaryFolder temp = new TemporaryFolder();
  Path baseDir;

  @Before
  public void setup() {
    baseDir = temp.getRoot().toPath();
  }

  private EngineExecutionResults executeTests() {
    return EngineTestKit.engine("junit-jupiter")
        .selectors(selectMethod("com.example.ValidFuzzTests#noCrashFuzz(byte[])"))
        .configurationParameter(
            "jazzer.instrument", "com.other.package.**,com.example.**,com.yet.another.package.*")
        .configurationParameter("jazzer.internal.basedir", baseDir.toAbsolutePath().toString())
        .execute();
  }

  @Test
  public void fuzzingEnabled() throws IOException {
    assumeFalse(System.getenv("JAZZER_FUZZ").isEmpty());

    EngineExecutionResults results = executeTests();

    results
        .containerEvents()
        .assertEventsMatchExactly(
            event(type(STARTED), container(ENGINE)),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ))),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ, NO_CRASH_FUZZ))),
            // Warning because the inputs directory hasn't been found in the source tree.
            event(
                type(REPORTING_ENTRY_PUBLISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, NO_CRASH_FUZZ))),
            // Warning because the inputs directory has been found on the classpath, but only in a
            // JAR.
            event(
                type(REPORTING_ENTRY_PUBLISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, NO_CRASH_FUZZ))),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, NO_CRASH_FUZZ)),
                finishedSuccessfully()),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ)),
                finishedSuccessfully()),
            event(type(FINISHED), container(ENGINE), finishedSuccessfully()));

    results
        .testEvents()
        .assertEventsMatchLooselyInOrder(
            event(
                type(DYNAMIC_TEST_REGISTERED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, NO_CRASH_FUZZ))),
            event(
                type(STARTED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, NO_CRASH_FUZZ, INVOCATION)),
                displayName("Fuzzing...")),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, NO_CRASH_FUZZ, INVOCATION)),
                displayName("Fuzzing..."),
                finishedSuccessfully()));

    // Verify that the engine created the generated corpus directory. As the fuzz test produces
    // coverage (but no crash), it should not be empty.
    Path generatedCorpus =
        baseDir.resolve(Paths.get(".cifuzz-corpus", "com.example.ValidFuzzTests", "noCrashFuzz"));
    assertThat(Files.isDirectory(generatedCorpus)).isTrue();
    try (Stream<Path> entries = Files.list(generatedCorpus)) {
      assertThat(entries).isNotEmpty();
    }
  }

  @Test
  public void fuzzingDisabled() {
    assumeTrue(System.getenv("JAZZER_FUZZ").isEmpty());

    EngineExecutionResults results = executeTests();

    results
        .containerEvents()
        .assertEventsMatchExactly(
            event(type(STARTED), container(ENGINE)),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ))),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ, NO_CRASH_FUZZ))),
            event(
                type(REPORTING_ENTRY_PUBLISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, NO_CRASH_FUZZ))),
            event(type(FINISHED), container(uniqueIdSubstrings(ENGINE, CLAZZ, NO_CRASH_FUZZ))),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ)),
                finishedSuccessfully()),
            event(type(FINISHED), container(ENGINE), finishedSuccessfully()));

    results
        .testEvents()
        .assertEventsMatchExactly(
            IntStream.rangeClosed(1, 6)
                .boxed()
                .flatMap(
                    i ->
                        Stream.of(
                            event(
                                type(DYNAMIC_TEST_REGISTERED),
                                test(uniqueIdSubstrings(ENGINE, CLAZZ, NO_CRASH_FUZZ))),
                            event(
                                type(STARTED),
                                test(
                                    uniqueIdSubstrings(
                                        ENGINE, CLAZZ, NO_CRASH_FUZZ, INVOCATION + i))),
                            event(
                                type(FINISHED),
                                test(
                                    uniqueIdSubstrings(
                                        ENGINE, CLAZZ, NO_CRASH_FUZZ, INVOCATION + i)),
                                finishedSuccessfully())))
                .toArray(Condition[]::new));

    // Verify that the generated corpus directory hasn't been created.
    Path generatedCorpus =
        baseDir.resolve(Paths.get(".cifuzz-corpus", "com.example.ValidFuzzTests", "noCrashFuzz"));
    assertThat(Files.notExists(generatedCorpus)).isTrue();
  }
}
