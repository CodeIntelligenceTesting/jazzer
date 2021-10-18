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
import com.code_intelligence.jazzer.utils.Utils;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.net.URLDecoder;
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
          "Expected the argument to --autofuzz to be a method reference (e.g. System.out::println)");
      System.exit(1);
    }
    methodReference = args[0];
    String[] parts = methodReference.split("::", 2);
    String className = parts[0];
    String methodNameAndOptionalDescriptor = parts[1];
    String methodName;
    String descriptor;
    int descriptorStart = methodNameAndOptionalDescriptor.indexOf('(');
    if (descriptorStart != -1) {
      methodName = methodNameAndOptionalDescriptor.substring(0, descriptorStart);
      // URL decode the descriptor to allow copy-pasting from javadoc links such as:
      // https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/lang/String.html#valueOf(char%5B%5D)
      try {
        descriptor =
            URLDecoder.decode(methodNameAndOptionalDescriptor.substring(descriptorStart), "UTF-8");
      } catch (UnsupportedEncodingException e) {
        // UTF-8 is always supported.
        e.printStackTrace();
        System.exit(1);
        return;
      }
    } else {
      methodName = methodNameAndOptionalDescriptor;
      descriptor = null;
    }

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
                        .filter(method
                            -> method.getName().equals(methodName)
                                && (descriptor == null
                                    || Utils.getReadableDescriptor(method).equals(descriptor)))
                        .toArray(Method[] ::new);
    if (targetMethods.length == 0) {
      if (descriptor == null) {
        System.err.printf("Failed to find accessible methods named %s in class %s for autofuzz.%n"
                + "Accessible methods:%n%s",
            methodName, className,
            Arrays.stream(targetClass.getMethods())
                .map(method
                    -> String.format(
                        "%s::%s", method.getDeclaringClass().getName(), method.getName()))
                .distinct()
                .collect(Collectors.joining(System.lineSeparator())));
      } else {
        System.err.printf("Failed to find accessible methods named %s in class %s for autofuzz.%n"
                + "Accessible methods with that name:%n%s",
            methodName, className,
            Arrays.stream(targetClass.getMethods())
                .filter(method -> method.getName().equals(methodName))
                .map(method
                    -> String.format("%s::%s%s", method.getDeclaringClass().getName(),
                        method.getName(), Utils.getReadableDescriptor(method)))
                .distinct()
                .collect(Collectors.joining(System.lineSeparator())));
      }
      System.exit(1);
    }
    throwsDeclarations =
        Arrays.stream(targetMethods)
            .collect(Collectors.toMap(method -> method, Method::getExceptionTypes));
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Throwable {
    Method targetMethod;
    if (targetMethods.length == 1) {
      targetMethod = targetMethods[0];
    } else {
      targetMethod = data.pickValue(targetMethods);
    }
    try {
      Meta.autofuzz(data, targetMethod);
      executionsSinceLastInvocation = 0;
    } catch (AutofuzzConstructionException e) {
      if (Meta.isDebug()) {
        e.printStackTrace();
      }
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
      cleanStackTraces(cause);
      throw cause;
    } catch (Throwable t) {
      System.err.println("Unexpected exception encountered during autofuzz");
      t.printStackTrace();
      System.exit(1);
    }
  }

  // Removes all stack trace elements that live in the Java standard library, internal JDK classes
  // or the autofuzz package from the bottom of all stack frames.
  private static void cleanStackTraces(Throwable t) {
    Throwable cause = t;
    while (cause != null) {
      StackTraceElement[] elements = cause.getStackTrace();
      int firstInterestingPos;
      for (firstInterestingPos = elements.length - 1; firstInterestingPos > 0;
           firstInterestingPos--) {
        String className = elements[firstInterestingPos].getClassName();
        if (!className.startsWith("com.code_intelligence.jazzer.autofuzz")
            && !className.startsWith("java.") && !className.startsWith("jdk.")) {
          break;
        }
      }
      cause.setStackTrace(Arrays.copyOfRange(elements, 0, firstInterestingPos + 1));
      cause = cause.getCause();
    }
  }
}
