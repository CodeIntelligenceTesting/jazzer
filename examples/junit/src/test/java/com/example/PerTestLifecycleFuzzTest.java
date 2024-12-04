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

package com.example;

import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

class PerTestLifecycleFuzzTest extends LifecycleRecordingTestBase {
  private static final ArrayList<String> events = new ArrayList<>();

  @BeforeAll
  static void beforeAll() {
    events.add("beforeAll");
  }

  @FuzzTest(maxExecutions = RUNS)
  void lifecycleFuzz(byte[] data) {
    addEvent("lifecycleFuzz");
  }

  @AfterAll
  static void afterAll() throws TestSuccessfulException {
    events.add("afterAll");

    ArrayList<String> expectedEvents = new ArrayList<>();
    expectedEvents.add("beforeAll");

    // When run from the command-line, the fuzz test is not separately executed on the empty seed.
    int fuzzingInstanceId = 1;
    // When run from the command-line, the fuzz test is not separately executed on the empty seed.
    if (IS_REGRESSION_TEST || IS_FUZZING_FROM_JUNIT) {
      expectedEvents.add("postProcessTestInstance on 1");
      expectedEvents.addAll(expectedBeforeEachEvents(1));
      expectedEvents.add("lifecycleFuzz on 1");
      expectedEvents.addAll(expectedAfterEachEvents(1));
      fuzzingInstanceId++;
    }
    if (IS_FUZZING_FROM_JUNIT || IS_FUZZING_FROM_COMMAND_LINE) {
      // With the PER_TEST lifecycle, fuzzing uses the instance provided by JUnit for all
      // executions.
      expectedEvents.add("postProcessTestInstance on " + fuzzingInstanceId);
      expectedEvents.addAll(expectedBeforeEachEvents(fuzzingInstanceId));
      for (int i = 1; i <= RUNS; i++) {
        expectedEvents.add("lifecycleFuzz on " + fuzzingInstanceId);
      }
      expectedEvents.addAll(expectedAfterEachEvents(fuzzingInstanceId));
    }

    expectedEvents.add("afterAll");

    assertThat(events).containsExactlyElementsIn(expectedEvents).inOrder();
    throw new TestSuccessfulException("Lifecycle methods invoked as expected");
  }

  @Override
  protected List<String> events() {
    return events;
  }
}
