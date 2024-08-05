/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
