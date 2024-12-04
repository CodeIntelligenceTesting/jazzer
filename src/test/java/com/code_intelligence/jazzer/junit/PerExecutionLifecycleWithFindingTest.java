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

import static org.junit.Assume.assumeFalse;
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
import static org.junit.platform.testkit.engine.EventType.SKIPPED;
import static org.junit.platform.testkit.engine.EventType.STARTED;
import static org.junit.platform.testkit.engine.TestExecutionResultConditions.cause;
import static org.junit.platform.testkit.engine.TestExecutionResultConditions.instanceOf;

import com.example.TestSuccessfulException;
import java.io.IOException;
import java.nio.file.Path;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.platform.testkit.engine.EngineExecutionResults;
import org.junit.platform.testkit.engine.EngineTestKit;
import org.junit.rules.TemporaryFolder;

public class PerExecutionLifecycleWithFindingTest {
  private static final String ENGINE = "engine:junit-jupiter";
  private static final String CLAZZ = "class:com.example.PerExecutionLifecycleWithFindingFuzzTest";
  private static final String DISABLED_FUZZ = "test-template:disabledFuzz([B)";
  private static final String LIFECYCLE_FUZZ = "test-template:lifecycleFuzz([B)";
  private static final String INVOCATION = "test-template-invocation:#";
  @Rule public TemporaryFolder temp = new TemporaryFolder();
  Path baseDir;

  @Before
  public void setup() {
    baseDir = temp.getRoot().toPath();
  }

  private EngineExecutionResults executeTests() {
    return EngineTestKit.engine("junit-jupiter")
        .selectors(selectClass("com.example.PerExecutionLifecycleWithFindingFuzzTest"))
        .configurationParameter(
            "jazzer.instrument", "com.other.package.**,com.example.**,com.yet.another.package.*")
        .configurationParameter("jazzer.internal.basedir", baseDir.toAbsolutePath().toString())
        .execute();
  }

  @Test
  public void fuzzingEnabled() {
    assumeFalse(System.getenv("JAZZER_FUZZ").isEmpty());

    EngineExecutionResults results = executeTests();

    results
        .containerEvents()
        .assertEventsMatchExactly(
            event(type(STARTED), container(ENGINE)),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ))),
            event(type(SKIPPED), container(uniqueIdSubstrings(ENGINE, CLAZZ, DISABLED_FUZZ))),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ, LIFECYCLE_FUZZ))),
            // Warning because the seed corpus directory hasn't been found.
            event(
                type(REPORTING_ENTRY_PUBLISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, LIFECYCLE_FUZZ))),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, LIFECYCLE_FUZZ)),
                finishedSuccessfully()),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ)),
                finishedWithFailure(instanceOf(TestSuccessfulException.class))),
            event(type(FINISHED), container(ENGINE), finishedSuccessfully()));

    results
        .testEvents()
        .assertEventsMatchExactly(
            event(
                type(DYNAMIC_TEST_REGISTERED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, LIFECYCLE_FUZZ))),
            event(
                type(STARTED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, LIFECYCLE_FUZZ, INVOCATION + 1)),
                displayName("<empty input>")),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, LIFECYCLE_FUZZ, INVOCATION + 1)),
                displayName("<empty input>"),
                finishedSuccessfully()),
            event(
                type(DYNAMIC_TEST_REGISTERED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, LIFECYCLE_FUZZ))),
            event(
                type(STARTED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, LIFECYCLE_FUZZ, INVOCATION + 2)),
                displayName("Fuzzing...")),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, LIFECYCLE_FUZZ, INVOCATION + 2)),
                displayName("Fuzzing..."),
                finishedWithFailure(
                    instanceOf(FuzzTestFindingException.class),
                    cause(instanceOf(IOException.class)))));
  }
}
