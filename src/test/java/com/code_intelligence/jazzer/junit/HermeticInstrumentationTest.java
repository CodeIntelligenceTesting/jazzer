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

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import java.nio.file.Path;
import java.util.regex.PatternSyntaxException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.platform.testkit.engine.EngineExecutionResults;
import org.junit.platform.testkit.engine.EngineTestKit;
import org.junit.rules.TemporaryFolder;

public class HermeticInstrumentationTest {
  private static final String ENGINE = "engine:junit-jupiter";
  private static final String CLAZZ = "class:com.example.HermeticInstrumentationFuzzTest";
  private static final String FUZZ_TEST_1 = "test-template:fuzzTest1([B)";
  private static final String FUZZ_TEST_2 = "test-template:fuzzTest2([B)";
  private static final String UNIT_TEST_1 = "method:unitTest1()";
  private static final String UNIT_TEST_2 = "method:unitTest2()";
  private static final String INVOCATION = "test-template-invocation:#1";
  @Rule public TemporaryFolder temp = new TemporaryFolder();
  Path baseDir;

  @Before
  public void setup() {
    baseDir = temp.getRoot().toPath();
  }

  private EngineExecutionResults executeTests() {
    return EngineTestKit.engine("junit-jupiter")
        .selectors(selectClass("com.example.HermeticInstrumentationFuzzTest"))
        .configurationParameter(
            "jazzer.instrument", "com.other.package.**,com.example.**,com.yet.another.package.*")
        .configurationParameter("jazzer.internal.basedir", baseDir.toAbsolutePath().toString())
        .configurationParameter("junit.jupiter.execution.parallel.enabled", "true")
        .execute();
  }

  @Test
  public void fuzzingDisabled() {
    assumeTrue(System.getenv("JAZZER_FUZZ") == null);

    EngineExecutionResults results = executeTests();

    results
        .containerEvents()
        .assertEventsMatchLoosely(
            event(type(STARTED), container(ENGINE)),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ))),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ, FUZZ_TEST_1))),
            event(
                type(REPORTING_ENTRY_PUBLISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, FUZZ_TEST_1))),
            event(type(FINISHED), container(uniqueIdSubstrings(ENGINE, CLAZZ, FUZZ_TEST_1))),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ, FUZZ_TEST_2))),
            event(
                type(REPORTING_ENTRY_PUBLISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, FUZZ_TEST_2))),
            event(type(FINISHED), container(uniqueIdSubstrings(ENGINE, CLAZZ, FUZZ_TEST_2))),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ)),
                finishedSuccessfully()),
            event(type(FINISHED), container(ENGINE), finishedSuccessfully()));

    results
        .testEvents()
        .assertEventsMatchLoosely(
            event(
                type(DYNAMIC_TEST_REGISTERED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, FUZZ_TEST_1))),
            event(
                type(STARTED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, FUZZ_TEST_1, INVOCATION)),
                displayName("<empty input>")),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, FUZZ_TEST_1, INVOCATION)),
                displayName("<empty input>"),
                finishedWithFailure(
                    instanceOf(FuzzTestFindingException.class),
                    cause(instanceOf(FuzzerSecurityIssueLow.class)))),
            event(type(STARTED), test(uniqueIdSubstrings(ENGINE, CLAZZ, UNIT_TEST_1))),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, UNIT_TEST_1)),
                finishedWithFailure(instanceOf(PatternSyntaxException.class))),
            event(
                type(DYNAMIC_TEST_REGISTERED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, FUZZ_TEST_2))),
            event(
                type(STARTED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, FUZZ_TEST_2, INVOCATION)),
                displayName("<empty input>")),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, FUZZ_TEST_2, INVOCATION)),
                displayName("<empty input>"),
                finishedWithFailure(
                    instanceOf(FuzzTestFindingException.class),
                    cause(instanceOf(FuzzerSecurityIssueLow.class)))),
            event(type(STARTED), test(uniqueIdSubstrings(ENGINE, CLAZZ, UNIT_TEST_2))),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, UNIT_TEST_2)),
                finishedWithFailure(instanceOf(PatternSyntaxException.class))));
  }
}
