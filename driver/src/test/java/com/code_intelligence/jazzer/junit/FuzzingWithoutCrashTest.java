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

import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectMethod;
import static org.junit.platform.testkit.engine.EventConditions.container;
import static org.junit.platform.testkit.engine.EventConditions.event;
import static org.junit.platform.testkit.engine.EventConditions.finishedSuccessfully;
import static org.junit.platform.testkit.engine.EventConditions.test;
import static org.junit.platform.testkit.engine.EventConditions.type;

import org.junit.Test;
import org.junit.platform.testkit.engine.EngineExecutionResults;
import org.junit.platform.testkit.engine.EngineTestKit;
import org.junit.platform.testkit.engine.EventType;

public class FuzzingWithoutCrashTest {
  private static EngineExecutionResults executeTests() {
    return EngineTestKit.engine("com.code_intelligence.jazzer")
        .selectors(selectMethod("com.example.ValidFuzzTests#noCrashFuzz(byte[])"))
        .configurationParameter(
            "jazzer.instrument", "com.other.package.**,com.example.**,com.yet.another.package.*")
        .execute();
  }

  @Test
  public void fuzzingEnabled() {
    assumeFalse(System.getenv("JAZZER_FUZZ").isEmpty());

    EngineExecutionResults results = executeTests();

    results.testEvents().debug().assertEventsMatchExactly(
        event(type(EventType.STARTED),
            test("com.example.ValidFuzzTests", "noCrashFuzz(byte[]) (Fuzzing)")),
        // Warning because the seed corpus directory hasn't been found.
        event(type(EventType.REPORTING_ENTRY_PUBLISHED),
            test("com.example.ValidFuzzTests", "noCrashFuzz(byte[]) (Fuzzing)")),
        event(type(EventType.FINISHED),
            test("com.example.ValidFuzzTests", "noCrashFuzz(byte[]) (Fuzzing)"),
            finishedSuccessfully()));
    results.containerEvents().debug().assertEventsMatchExactly(
        event(type(EventType.STARTED), container("com.code_intelligence.jazzer")),
        event(type(EventType.FINISHED), container("com.code_intelligence.jazzer")));
  }

  @Test
  public void fuzzingDisabled() {
    assumeTrue(System.getenv("JAZZER_FUZZ").isEmpty());

    EngineExecutionResults results = executeTests();

    // When fuzzing isn't requested, the Jazzer test engine doesn't discover any tests.
    results.testEvents().debug().assertEventsMatchExactly();
    results.containerEvents().debug().assertEventsMatchExactly(
        event(type(EventType.STARTED), container("com.code_intelligence.jazzer")),
        event(type(EventType.FINISHED), container("com.code_intelligence.jazzer"),
            finishedSuccessfully()));
  }
}
