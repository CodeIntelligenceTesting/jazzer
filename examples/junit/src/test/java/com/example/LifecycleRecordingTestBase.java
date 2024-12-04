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
import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toList;

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.example.LifecycleRecordingTestBase.LifecycleCallbacks1;
import com.example.LifecycleRecordingTestBase.LifecycleCallbacks2;
import com.example.LifecycleRecordingTestBase.LifecycleCallbacks3;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
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
@ExtendWith(LifecycleRecordingTestBase.LifecycleInstancePostProcessor.class)
@ExtendWith(LifecycleCallbacks1.class)
@ExtendWith(LifecycleCallbacks2.class)
@ExtendWith(LifecycleCallbacks3.class)
public abstract class LifecycleRecordingTestBase {

  protected static final long RUNS = 3;
  protected static final boolean IS_REGRESSION_TEST = "".equals(System.getenv("JAZZER_FUZZ"));
  protected static final boolean IS_FUZZING_FROM_COMMAND_LINE =
      System.getenv("JAZZER_FUZZ") == null;
  protected static final boolean IS_FUZZING_FROM_JUNIT =
      !IS_FUZZING_FROM_COMMAND_LINE && !IS_REGRESSION_TEST;

  private static int nextInstanceId = 1;
  private final int instanceId = nextInstanceId++;

  protected abstract List<String> events();

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

  static void assertConsistentTestInstances(ExtensionContext extensionContext) {
    assertThat(extensionContext.getTestInstance().get())
        .isSameInstanceAs(extensionContext.getRequiredTestInstance());
    assertThat(extensionContext.getTestInstances().get())
        .isSameInstanceAs(extensionContext.getRequiredTestInstances());
    assertThat(extensionContext.getRequiredTestInstances().getAllInstances())
        .containsExactly(extensionContext.getRequiredTestInstance());
  }

  protected void addEvent(String what) {
    events().add(what + " on " + instanceId);
  }

  @Disabled
  @FuzzTest
  void disabledFuzz(byte[] data) {
    addEvent("disabledFuzz");
    throw new AssertionError("This test should not be executed");
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

  static class LifecycleInstancePostProcessor implements TestInstancePostProcessor {
    @Override
    public void postProcessTestInstance(Object o, ExtensionContext extensionContext) {
      assertThat(extensionContext.getTestInstance()).isEmpty();
      assertThat(extensionContext.getTestInstances()).isEmpty();
      ((LifecycleRecordingTestBase) o).addEvent("postProcessTestInstance");
    }
  }

  static class LifecycleCallbacks1 implements BeforeEachCallback, AfterEachCallback {
    @Override
    public void beforeEach(ExtensionContext extensionContext) {
      assertConsistentTestInstances(extensionContext);
      ((LifecycleRecordingTestBase) extensionContext.getRequiredTestInstance())
          .addEvent("beforeEachCallback1");
    }

    @Override
    public void afterEach(ExtensionContext extensionContext) {
      assertConsistentTestInstances(extensionContext);
      ((LifecycleRecordingTestBase) extensionContext.getRequiredTestInstance())
          .addEvent("afterEachCallback1");
    }
  }

  static class LifecycleCallbacks2 implements BeforeEachCallback, AfterEachCallback {
    @Override
    public void beforeEach(ExtensionContext extensionContext) {
      assertConsistentTestInstances(extensionContext);
      ((LifecycleRecordingTestBase) extensionContext.getRequiredTestInstance())
          .addEvent("beforeEachCallback2");
    }

    @Override
    public void afterEach(ExtensionContext extensionContext) {
      assertConsistentTestInstances(extensionContext);
      ((LifecycleRecordingTestBase) extensionContext.getRequiredTestInstance())
          .addEvent("afterEachCallback2");
    }
  }

  static class LifecycleCallbacks3 implements BeforeEachCallback, AfterEachCallback {
    @Override
    public void beforeEach(ExtensionContext extensionContext) {
      assertConsistentTestInstances(extensionContext);
      ((LifecycleRecordingTestBase) extensionContext.getRequiredTestInstance())
          .addEvent("beforeEachCallback3");
    }

    @Override
    public void afterEach(ExtensionContext extensionContext) {
      assertConsistentTestInstances(extensionContext);
      ((LifecycleRecordingTestBase) extensionContext.getRequiredTestInstance())
          .addEvent("afterEachCallback3");
    }
  }
}
