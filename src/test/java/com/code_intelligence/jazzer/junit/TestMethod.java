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

import static org.junit.platform.engine.discovery.DiscoverySelectors.selectMethod;

import java.lang.reflect.Method;

/**
 * Small class that allows us to capture the methods that we're using as test data. We need similar
 * but slightly different data at various points: 1. the method name with parameters for finding the
 * method initially and for referring to it in JUnit 2. the method name without parameters for the
 * findings directories
 */
public class TestMethod {
  Method method;
  String nameWithParams;

  TestMethod(String className, String methodName) {
    nameWithParams = methodName;
    method = selectMethod(className + "#" + methodName).getJavaMethod();
  }

  /** Returns the {@link org.junit.platform.engine.TestDescriptor} ID for this method */
  String getDescriptorId() {
    return "test-template:" + nameWithParams;
  }

  /** Returns just the name of the method without parameters */
  String getName() {
    return method.getName();
  }
}
