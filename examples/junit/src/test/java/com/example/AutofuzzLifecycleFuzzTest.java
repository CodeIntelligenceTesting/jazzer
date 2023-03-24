/*
 * Copyright 2023 Code Intelligence GmbH
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
