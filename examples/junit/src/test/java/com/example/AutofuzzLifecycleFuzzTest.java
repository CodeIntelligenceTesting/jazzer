/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.junit.FuzzTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestInstancePostProcessor;

@TestMethodOrder(MethodOrderer.MethodName.class)
@ExtendWith(AutofuzzLifecycleFuzzTest.AutofuzzLifecycleInstancePostProcessor.class)
class AutofuzzLifecycleFuzzTest {
  // Use a TestInstancePostProcessor to inject an object into the JUnit test instance,
  // simulating other JUnit extensions like the Spring Boot Test, to check that autofuzz
  // invokes the test function on the correct instance.
  private Object injectedObject;

  @FuzzTest(maxDuration = "1s")
  void autofuzzLifecycleFuzz(String ignored, String ignoredAsWell) {
    Assertions.assertNotNull(injectedObject);
  }

  static class AutofuzzLifecycleInstancePostProcessor implements TestInstancePostProcessor {
    @Override
    public void postProcessTestInstance(Object o, ExtensionContext extensionContext) {
      ((AutofuzzLifecycleFuzzTest) o).injectedObject = new Object();
    }
  }
}
