/*
 * Copyright 2022 Code Intelligence GmbH
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
import static com.google.common.truth.Truth8.assertThat;
import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toList;

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.jazzer.junit.Lifecycle;
import com.example.PerExecutionLifecycleWithFindingFuzzTest.LifecycleCallbacks1;
import com.example.PerExecutionLifecycleWithFindingFuzzTest.LifecycleCallbacks2;
import com.example.PerExecutionLifecycleWithFindingFuzzTest.LifecycleCallbacks3;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestInstancePostProcessor;

@TestMethodOrder(MethodOrderer.MethodName.class)
@ExtendWith(PerExecutionLifecycleWithFindingFuzzTest.LifecycleInstancePostProcessor.class)
@ExtendWith(LifecycleCallbacks1.class)
@ExtendWith(LifecycleCallbacks2.class)
@ExtendWith(LifecycleCallbacks3.class)
class PerExecutionLifecycleWithFindingFuzzTest {
  private static final ArrayList<String> events = new ArrayList<>();
  private static final long RUNS = 3;
  private static int nextInstanceId = 1;
  private final int instanceId = nextInstanceId++;

  @BeforeAll
  static void beforeAll() {
    events.add("beforeAll");
  }

  private void addEvent(String what) {
    events.add(what + " on " + instanceId);
  }

  @BeforeEach
  void beforeEach1() {
    addEvent("beforeEach1");
  }

  @BeforeEach
  void beforeEach2() {
    addEvent("beforeEach2");
  }

  @BeforeEach
  void beforeEach3() {
    addEvent("beforeEach3");
  }

  @Disabled
  @FuzzTest
  void disabledFuzz(byte[] data) {
    addEvent("disabledFuzz");
    throw new AssertionError("This test should not be executed");
  }

  @FuzzTest(maxExecutions = RUNS, lifecycle = Lifecycle.PER_EXECUTION)
  void lifecycleFuzz(byte[] data) throws IOException {
    addEvent("lifecycleFuzz");
    if (data.length != 0) {
      throw new IOException(
          "Planted finding on first non-trivial input (second execution during fuzzing)");
    }
  }

  @AfterEach
  void afterEach1() {
    addEvent("afterEach1");
  }

  @AfterEach
  void afterEach2() {
    addEvent("afterEach2");
  }

  @AfterEach
  void afterEach3() {
    addEvent("afterEach3");
  }

  static List<String> expectedBeforeEachEvents(int instanceId) {
    return Stream.of(
            "beforeEachCallback1",
            "beforeEachCallback2",
            "beforeEachCallback3",
            "beforeEach1",
            "beforeEach2",
            "beforeEach3")
        .map(s -> s + " on " + instanceId)
        .collect(collectingAndThen(toList(), Collections::unmodifiableList));
  }

  static List<String> expectedAfterEachEvents(int instanceId) {
    return Stream.of(
            "afterEach1",
            "afterEach2",
            "afterEach3",
            "afterEachCallback3",
            "afterEachCallback2",
            "afterEachCallback1")
        .map(s -> s + " on " + instanceId)
        .collect(collectingAndThen(toList(), Collections::unmodifiableList));
  }

  @AfterAll
  static void afterAll() throws TestSuccessfulException {
    events.add("afterAll");

    boolean isRegressionTest = "".equals(System.getenv("JAZZER_FUZZ"));
    boolean isFuzzingFromCommandLine = System.getenv("JAZZER_FUZZ") == null;
    boolean isFuzzingFromJUnit = !isFuzzingFromCommandLine && !isRegressionTest;

    ArrayList<String> expectedEvents = new ArrayList<>();
    expectedEvents.add("beforeAll");

    int firstFuzzingInstanceId = 1;
    // When run from the command-line, the fuzz test is not separately executed on the empty seed.
    if (isRegressionTest || isFuzzingFromJUnit) {
      expectedEvents.add("postProcessTestInstance on 1");
      expectedEvents.addAll(expectedBeforeEachEvents(1));
      expectedEvents.add("lifecycleFuzz on 1");
      expectedEvents.addAll(expectedAfterEachEvents(1));
      firstFuzzingInstanceId++;
    }
    if (isFuzzingFromJUnit || isFuzzingFromCommandLine) {
      expectedEvents.add("postProcessTestInstance on " + firstFuzzingInstanceId);
      expectedEvents.addAll(expectedBeforeEachEvents(firstFuzzingInstanceId));
      // The fuzz test fails during the second run.
      for (int i = 1; i <= 2; i++) {
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

  static void assertConsistentTestInstances(ExtensionContext extensionContext) {
    assertThat(extensionContext.getTestInstance().get())
        .isSameInstanceAs(extensionContext.getRequiredTestInstance());
    assertThat(extensionContext.getTestInstances().get())
        .isSameInstanceAs(extensionContext.getRequiredTestInstances());
    assertThat(extensionContext.getRequiredTestInstances().getAllInstances())
        .containsExactly(extensionContext.getRequiredTestInstance());
  }

  static class LifecycleInstancePostProcessor implements TestInstancePostProcessor {
    @Override
    public void postProcessTestInstance(Object o, ExtensionContext extensionContext) {
      assertThat(extensionContext.getTestInstance()).isEmpty();
      assertThat(extensionContext.getTestInstances()).isEmpty();
      ((PerExecutionLifecycleWithFindingFuzzTest) o).addEvent("postProcessTestInstance");
    }
  }

  static class LifecycleCallbacks1 implements BeforeEachCallback, AfterEachCallback {
    @Override
    public void beforeEach(ExtensionContext extensionContext) {
      assertConsistentTestInstances(extensionContext);
      ((PerExecutionLifecycleWithFindingFuzzTest) extensionContext.getRequiredTestInstance())
          .addEvent("beforeEachCallback1");
    }

    @Override
    public void afterEach(ExtensionContext extensionContext) {
      assertConsistentTestInstances(extensionContext);
      ((PerExecutionLifecycleWithFindingFuzzTest) extensionContext.getRequiredTestInstance())
          .addEvent("afterEachCallback1");
    }
  }

  static class LifecycleCallbacks2 implements BeforeEachCallback, AfterEachCallback {
    @Override
    public void beforeEach(ExtensionContext extensionContext) {
      assertConsistentTestInstances(extensionContext);
      ((PerExecutionLifecycleWithFindingFuzzTest) extensionContext.getRequiredTestInstance())
          .addEvent("beforeEachCallback2");
    }

    @Override
    public void afterEach(ExtensionContext extensionContext) {
      assertConsistentTestInstances(extensionContext);
      ((PerExecutionLifecycleWithFindingFuzzTest) extensionContext.getRequiredTestInstance())
          .addEvent("afterEachCallback2");
    }
  }

  static class LifecycleCallbacks3 implements BeforeEachCallback, AfterEachCallback {
    @Override
    public void beforeEach(ExtensionContext extensionContext) {
      assertConsistentTestInstances(extensionContext);
      ((PerExecutionLifecycleWithFindingFuzzTest) extensionContext.getRequiredTestInstance())
          .addEvent("beforeEachCallback3");
    }

    @Override
    public void afterEach(ExtensionContext extensionContext) {
      assertConsistentTestInstances(extensionContext);
      ((PerExecutionLifecycleWithFindingFuzzTest) extensionContext.getRequiredTestInstance())
          .addEvent("afterEachCallback3");
    }
  }
}
