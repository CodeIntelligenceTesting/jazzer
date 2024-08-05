/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.jazzer.junit.Lifecycle;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

class PerExecutionLifecycleFuzzTest extends LifecycleRecordingTestBase {
  private static final ArrayList<String> events = new ArrayList<>();

  @BeforeAll
  static void beforeAll() {
    events.add("beforeAll");
  }

  @FuzzTest(maxExecutions = RUNS, lifecycle = Lifecycle.PER_EXECUTION)
  void lifecycleFuzz(byte[] data) {
    addEvent("lifecycleFuzz");
  }

  @AfterAll
  static void afterAll() throws TestSuccessfulException {
    events.add("afterAll");

    ArrayList<String> expectedEvents = new ArrayList<>();
    expectedEvents.add("beforeAll");

    int firstFuzzingInstanceId = 1;
    // When run from the command-line, the fuzz test is not separately executed on the empty seed.
    if (IS_REGRESSION_TEST || IS_FUZZING_FROM_JUNIT) {
      expectedEvents.add("postProcessTestInstance on 1");
      expectedEvents.addAll(expectedBeforeEachEvents(1));
      expectedEvents.add("lifecycleFuzz on 1");
      expectedEvents.addAll(expectedAfterEachEvents(1));
      firstFuzzingInstanceId++;
    }
    if (IS_FUZZING_FROM_JUNIT || IS_FUZZING_FROM_COMMAND_LINE) {
      // See the comment in JUnitLifecycleMethodsInvoker#beforeFirstExecution() for an explanation
      // of why we see the lifecycle events on firstFuzzingInstanceId.
      expectedEvents.add("postProcessTestInstance on " + firstFuzzingInstanceId);
      expectedEvents.addAll(expectedBeforeEachEvents(firstFuzzingInstanceId));
      for (int i = 1; i <= RUNS; i++) {
        int expectedId = firstFuzzingInstanceId + i;
        expectedEvents.add("postProcessTestInstance on " + expectedId);
        expectedEvents.addAll(expectedBeforeEachEvents(expectedId));
        expectedEvents.add("lifecycleFuzz on " + expectedId);
        expectedEvents.addAll(expectedAfterEachEvents(expectedId));
      }
      expectedEvents.addAll(expectedAfterEachEvents(firstFuzzingInstanceId));
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
