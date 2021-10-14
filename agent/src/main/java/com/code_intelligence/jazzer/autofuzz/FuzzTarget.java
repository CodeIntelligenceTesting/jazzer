// Copyright 2021 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.autofuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

public class FuzzTarget {
  private static final long MAX_EXECUTIONS_WITHOUT_INVOCATION = 100;

  private static String methodReference;
  private static Method[] targetMethods;
  private static Map<Method, Class<?>[]> throwsDeclarations;
  private static long executionsSinceLastInvocation = 0;

  public static void fuzzerInitialize(String[] args) {
    if (args.length != 1 || !args[0].contains("::")) {
      System.err.println(
          "Expected the argument to --autofuzz to be a method reference (e.g. System.out::println");
      System.exit(1);
    }
    methodReference = args[0];
    String[] parts = methodReference.split("::", 2);
    String className = parts[0];
    String methodName = parts[1];

    Class<?> targetClass;
    try {
      targetClass = Thread.currentThread().getContextClassLoader().loadClass(className);
    } catch (ClassNotFoundException e) {
      System.err.printf(
          "Failed to find class %s for autofuzz, please ensure it is contained in the classpath "
              + "specified with --cp and specify the full package name%n",
          className);
      e.printStackTrace();
      System.exit(1);
      return;
    }

    targetMethods = Arrays.stream(targetClass.getMethods())
                        .filter(method -> method.getName().equals(methodName))
                        .toArray(Method[] ::new);
    if (targetMethods.length == 0) {
      System.err.printf("Failed to find accessible methods named %s in class %s for autofuzz",
          methodName, className);
    }
    throwsDeclarations =
        Arrays.stream(targetMethods)
            .collect(Collectors.toMap(method -> method, Method::getExceptionTypes));
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Throwable {
    Method targetMethod = data.pickValue(targetMethods);
    try {
      Meta.autofuzz(data, targetMethod);
      executionsSinceLastInvocation = 0;
    } catch (AutofuzzConstructionException ignored) {
      // Ignore exceptions thrown while constructing the parameters for the target method. We can
      // only guess how to generate valid parameters and any exceptions thrown while doing so
      // are most likely on us. However, if this happens too often, Autofuzz got stuck and we should
      // let the user know.
      executionsSinceLastInvocation++;
      if (executionsSinceLastInvocation >= MAX_EXECUTIONS_WITHOUT_INVOCATION) {
        System.err.printf("Failed to generate valid arguments to '%s' in %d attempts; giving up%n",
            methodReference, executionsSinceLastInvocation);
        System.exit(1);
      }
    } catch (AutofuzzInvocationException e) {
      executionsSinceLastInvocation = 0;
      Throwable cause = e.getCause();
      Class<?> causeClass = cause.getClass();
      // Do not report exceptions declared to be thrown by the method under test.
      for (Class<?> declaredThrow : throwsDeclarations.get(targetMethod)) {
        if (declaredThrow.isAssignableFrom(causeClass)) {
          return;
        }
      }
      throw cause;
    } catch (Throwable t) {
      System.err.println("Unexpected exception encountered during autofuzz");
      t.printStackTrace();
      System.exit(1);
    }
  }
}
