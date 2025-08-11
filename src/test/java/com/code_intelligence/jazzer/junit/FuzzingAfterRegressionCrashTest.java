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

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.platform.testkit.engine.EngineExecutionResults;
import org.junit.platform.testkit.engine.EngineTestKit;
import org.junit.rules.TemporaryFolder;

public class FuzzingAfterRegressionCrashTest {
  private static final String ENGINE = "engine:junit-jupiter";
  private static final String INVOCATION = "test-template-invocation:#";
  private static final String CLAZZ_NAME = "com.example.FuzzTestWithCrashTest";
  private static final String CLAZZ = "class:" + CLAZZ_NAME;
  private static final TestMethod CRASH_FUZZ =
      new TestMethod(CLAZZ_NAME, "crashFuzz(com.code_intelligence.jazzer.api.FuzzedDataProvider)");

  @Rule public TemporaryFolder temp = new TemporaryFolder();
  Path baseDir;

  @Before
  public void setup() throws IOException {
    baseDir = temp.getRoot().toPath();
  }

  private EngineExecutionResults executeTests() {
    return EngineTestKit.engine("junit-jupiter")
        .selectors(selectClass(CLAZZ_NAME))
        .configurationParameter(
            "jazzer.instrument", "com.other.package.**,com.example.**,com.yet.another.package.*")
        .configurationParameter("jazzer.internal.basedir", baseDir.toAbsolutePath().toString())
        .execute();
  }

  @Test
  public void fuzzingAfterRegressionCrashTest() throws IOException {
    EngineExecutionResults results = executeTests();
    results
        .containerEvents()
        .assertEventsMatchExactly(
            event(type(STARTED), container(ENGINE)),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ))),
            event(
                type(STARTED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, CRASH_FUZZ.getDescriptorId()))),
            event(
                type(REPORTING_ENTRY_PUBLISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, CRASH_FUZZ.getDescriptorId()))),
            event(
                type(REPORTING_ENTRY_PUBLISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, CRASH_FUZZ.getDescriptorId()))),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, CRASH_FUZZ.getDescriptorId())),
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
                test(uniqueIdSubstrings(ENGINE, CLAZZ, CRASH_FUZZ.getDescriptorId())),
                displayName("<empty input>")),
            event(
                type(STARTED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, CRASH_FUZZ.getDescriptorId(), INVOCATION)),
                displayName("<empty input>")),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, CRASH_FUZZ.getDescriptorId(), INVOCATION)),
                displayName("<empty input>"),
                finishedSuccessfully()),
            event(
                type(DYNAMIC_TEST_REGISTERED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, CRASH_FUZZ.getDescriptorId())),
                displayName("crash")),
            event(
                type(STARTED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, CRASH_FUZZ.getDescriptorId(), INVOCATION)),
                displayName("crash")),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, CRASH_FUZZ.getDescriptorId(), INVOCATION)),
                displayName("crash"),
                finishedWithFailure(
                    instanceOf(FuzzTestFindingException.class),
                    cause(instanceOf(FuzzerSecurityIssueLow.class)))),
            event(
                type(DYNAMIC_TEST_REGISTERED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, CRASH_FUZZ.getDescriptorId())),
                displayName("Fuzzing...")),
            event(
                type(STARTED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, CRASH_FUZZ.getDescriptorId(), INVOCATION)),
                displayName("Fuzzing...")),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, CRASH_FUZZ.getDescriptorId(), INVOCATION)),
                displayName("Fuzzing..."),
                finishedWithFailure(
                    instanceOf(FuzzTestFindingException.class),
                    cause(instanceOf(FuzzerSecurityIssueLow.class)))));

    try (Stream<Path> stream =
        Files.list(baseDir).filter(f -> f.getFileName().toString().startsWith("crash-"))) {
      List<Path> entries = stream.collect(Collectors.toList());

      // Ensure that there is at least one crash file.
      assertThat(entries).hasSize(1);

      // Ensure that no crash file has 0-bytes (aka. <empty input>).
      // This is to catch the bug where if the last input in regression mode caused a crash, Jazzer
      // would register a crash for the very first input in fuzzing mode, which is an empty input.
      entries.forEach(
          entry -> {
            try {
              assertThat(Files.size(entry)).isGreaterThan(0);
            } catch (IOException e) {
              throw new RuntimeException(e);
            }
          });
    }
  }
}
