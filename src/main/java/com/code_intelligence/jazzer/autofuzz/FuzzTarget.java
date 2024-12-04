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

package com.code_intelligence.jazzer.autofuzz;

import com.code_intelligence.jazzer.api.AutofuzzConstructionException;
import com.code_intelligence.jazzer.api.AutofuzzInvocationException;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.utils.Log;
import com.code_intelligence.jazzer.utils.SimpleGlobMatcher;
import com.code_intelligence.jazzer.utils.Utils;
import java.io.Closeable;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class FuzzTarget {
  private static final String AUTOFUZZ_REPRODUCER_TEMPLATE =
      "public class Crash_%1$s {\n"
          + "  public static void main(String[] args) throws Throwable {\n"
          + "    Crash_%1$s.class.getClassLoader().setDefaultAssertionStatus(true);\n"
          + "    %2$s;\n"
          + "  }\n"
          + "}";
  private static final long MAX_EXECUTIONS_WITHOUT_INVOCATION = 100;

  private static Meta meta;
  private static String methodReference;
  private static Executable[] targetExecutables;
  private static Object targetInstance;
  private static Map<Executable, Class<?>[]> throwsDeclarations;
  private static Set<SimpleGlobMatcher> ignoredExceptionMatchers;
  private static long executionsSinceLastInvocation = 0;

  public static void fuzzerInitialize(String[] args) {
    if (args.length == 0 || !args[0].contains("::")) {
      Log.error(
          "Expected the argument to --autofuzz to be a method reference (e.g."
              + " System.out::println)");
      System.exit(1);
    }
    String methodSignature = args[0];
    String[] parts = methodSignature.split("::", 2);
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
        Log.error(e);
        System.exit(1);
        return;
      }
    } else {
      methodName = methodNameAndOptionalDescriptor;
      descriptor = null;
    }

    Class<?> targetClassTemp = null;
    String targetClassName = className;
    do {
      try {
        targetClassTemp = Class.forName(targetClassName);
      } catch (ClassNotFoundException e) {
        int classSeparatorIndex = targetClassName.lastIndexOf(".");
        if (classSeparatorIndex == -1) {
          Log.error(
              String.format(
                  "Failed to find class %s for autofuzz, please ensure it is contained in the"
                      + " classpath specified with --cp and specify the full package name",
                  className));
          System.exit(1);
          return;
        }
        StringBuilder classNameBuilder = new StringBuilder(targetClassName);
        classNameBuilder.setCharAt(classSeparatorIndex, '$');
        targetClassName = classNameBuilder.toString();
      }
    } while (targetClassTemp == null);
    final Class<?> targetClass = targetClassTemp;

    AccessibleObjectLookup lookup = new AccessibleObjectLookup(targetClass);

    Executable[] executables;
    boolean isConstructor = methodName.equals("new");
    // We filter out inherited methods, which can lead to unexpected results when autofuzzing a
    // method by name without a descriptor. If desired, these can be autofuzzed explicitly by
    // referencing the parent class. If a descriptor is provided, we also allow fuzzing non-public
    // methods. This is necessary e.g. when using Autofuzz on a package-private JUnit @FuzzTest
    // method.
    if (isConstructor) {
      executables =
          Arrays.stream(lookup.getAccessibleConstructors(targetClass))
              .filter(constructor -> constructor.getDeclaringClass().equals(targetClass))
              .filter(
                  constructor ->
                      (descriptor == null && Modifier.isPublic(constructor.getModifiers()))
                          || Utils.getReadableDescriptor(constructor).equals(descriptor))
              .toArray(Executable[]::new);
    } else {
      executables =
          Arrays.stream(lookup.getAccessibleMethods(targetClass))
              .filter(method -> method.getDeclaringClass().equals(targetClass))
              .filter(
                  method ->
                      method.getName().equals(methodName)
                          && ((descriptor == null && Modifier.isPublic(method.getModifiers()))
                              || Utils.getReadableDescriptor(method).equals(descriptor)))
              .toArray(Executable[]::new);
    }
    if (executables.length == 0) {
      if (isConstructor) {
        if (descriptor == null) {
          Log.error(
              String.format("Failed to find constructors in class %s for autofuzz.%n", className));
        } else {
          Log.error(
              String.format(
                  "Failed to find constructors with signature %s in class %s for autofuzz.%n"
                      + "Public constructors declared by the class:%n%s",
                  descriptor,
                  className,
                  Arrays.stream(lookup.getAccessibleConstructors(targetClass))
                      .filter(constructor -> Modifier.isPublic(constructor.getModifiers()))
                      .filter(constructor -> constructor.getDeclaringClass().equals(targetClass))
                      .map(
                          method ->
                              String.format(
                                  "%s::new%s",
                                  method.getDeclaringClass().getName(),
                                  Utils.getReadableDescriptor(method)))
                      .distinct()
                      .collect(Collectors.joining(System.lineSeparator()))));
        }
      } else {
        if (descriptor == null) {
          Log.error(
              String.format(
                  "Failed to find methods named %s in class %s for autofuzz.%n"
                      + "Public methods declared by the class:%n%s",
                  methodName,
                  className,
                  Arrays.stream(lookup.getAccessibleMethods(targetClass))
                      .filter(method -> Modifier.isPublic(method.getModifiers()))
                      .filter(method -> method.getDeclaringClass().equals(targetClass))
                      .map(
                          method ->
                              String.format(
                                  "%s::%s", method.getDeclaringClass().getName(), method.getName()))
                      .distinct()
                      .collect(Collectors.joining(System.lineSeparator()))));
        } else {
          Log.error(
              String.format(
                  "Failed to find public methods named %s with signature %s in class %s for"
                      + " autofuzz.%nPublic methods with that name:%n%s",
                  methodName,
                  descriptor,
                  className,
                  Arrays.stream(lookup.getAccessibleMethods(targetClass))
                      .filter(method -> Modifier.isPublic(method.getModifiers()))
                      .filter(method -> method.getDeclaringClass().equals(targetClass))
                      .filter(method -> method.getName().equals(methodName))
                      .map(
                          method ->
                              String.format(
                                  "%s::%s%s",
                                  method.getDeclaringClass().getName(),
                                  method.getName(),
                                  Utils.getReadableDescriptor(method)))
                      .distinct()
                      .collect(Collectors.joining(System.lineSeparator()))));
        }
      }
      System.exit(1);
    }

    Set<SimpleGlobMatcher> ignoredExceptionGlobMatchers =
        Arrays.stream(args)
            .skip(1)
            .filter(s -> s.contains("*"))
            .map(SimpleGlobMatcher::new)
            .collect(Collectors.toSet());

    List<Class<?>> alwaysIgnore =
        Arrays.stream(args)
            .skip(1)
            .filter(s -> !s.contains("*"))
            .map(
                name -> {
                  try {
                    return ClassLoader.getSystemClassLoader().loadClass(name);
                  } catch (ClassNotFoundException e) {
                    Log.error(
                        String.format(
                            "Failed to find class '%s' specified in --autofuzz_ignore", name));
                    System.exit(1);
                  }
                  throw new Error("Not reached");
                })
            .collect(Collectors.toList());

    Map<Executable, Class<?>[]> ignoredExceptionClasses =
        Arrays.stream(executables)
            .collect(
                Collectors.toMap(
                    method -> method,
                    method ->
                        Stream.concat(
                                Arrays.stream(method.getExceptionTypes()), alwaysIgnore.stream())
                            .toArray(Class[]::new)));

    setTarget(
        executables, null, methodSignature, ignoredExceptionGlobMatchers, ignoredExceptionClasses);
  }

  /**
   * Set the target executables to (auto-)fuzz. This method is primarily used by the JUnit
   * integration to set the target class and method passed in by the test framework.
   */
  public static void setTarget(
      Executable[] targetExecutables,
      Object targetInstance,
      String methodReference,
      Set<SimpleGlobMatcher> ignoredExceptionMatchers,
      Map<Executable, Class<?>[]> throwsDeclarations) {
    Class<?> targetClass = null;
    for (Executable executable : targetExecutables) {
      if (targetClass != null && !targetClass.equals(executable.getDeclaringClass())) {
        throw new IllegalStateException(
            "All target executables must be declared in the same class");
      }
      targetClass = executable.getDeclaringClass();
      executable.setAccessible(true);
    }

    FuzzTarget.meta = new Meta(targetClass);
    FuzzTarget.targetExecutables = targetExecutables;
    FuzzTarget.targetInstance = targetInstance;
    FuzzTarget.methodReference = methodReference;
    FuzzTarget.ignoredExceptionMatchers = ignoredExceptionMatchers;
    FuzzTarget.throwsDeclarations = throwsDeclarations;
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Throwable {
    AutofuzzCodegenVisitor codegenVisitor = null;
    if (Meta.IS_DEBUG) {
      codegenVisitor = new AutofuzzCodegenVisitor();
    }
    fuzzerTestOneInput(data, codegenVisitor);
    if (codegenVisitor != null) {
      Log.println(codegenVisitor.generate());
    }
  }

  public static void dumpReproducer(FuzzedDataProvider data, String reproducerPath, String sha) {
    AutofuzzCodegenVisitor codegenVisitor = new AutofuzzCodegenVisitor();
    try {
      fuzzerTestOneInput(data, codegenVisitor);
    } catch (Throwable ignored) {
    }
    String javaSource = String.format(AUTOFUZZ_REPRODUCER_TEMPLATE, sha, codegenVisitor.generate());
    Path javaPath = Paths.get(reproducerPath, String.format("Crash_%s.java", sha));
    try {
      Files.write(javaPath, javaSource.getBytes(StandardCharsets.UTF_8));
    } catch (IOException e) {
      Log.error(String.format("Failed to write Java reproducer to %s%n", javaPath), e);
    }
    Log.println(
        String.format(
            "reproducer_path='%s'; Java reproducer written to %s%n", reproducerPath, javaPath));
  }

  private static void fuzzerTestOneInput(
      FuzzedDataProvider data, AutofuzzCodegenVisitor codegenVisitor) throws Throwable {
    Executable targetExecutable;
    if (FuzzTarget.targetExecutables.length == 1) {
      targetExecutable = FuzzTarget.targetExecutables[0];
    } else {
      targetExecutable = data.pickValue(FuzzTarget.targetExecutables);
    }
    Object returnValue = null;
    try {
      if (targetExecutable instanceof Method) {
        if (targetInstance != null) {
          returnValue =
              meta.autofuzz(data, (Method) targetExecutable, targetInstance, codegenVisitor);
        } else {
          returnValue = meta.autofuzz(data, (Method) targetExecutable, codegenVisitor);
        }
      } else {
        // No targetInstance for constructors possible.
        returnValue = meta.autofuzz(data, (Constructor<?>) targetExecutable, codegenVisitor);
      }
      executionsSinceLastInvocation = 0;
    } catch (AutofuzzConstructionException e) {
      if (Meta.IS_DEBUG) {
        Log.error(e);
      }
      // Ignore exceptions thrown while constructing the parameters for the target method. We can
      // only guess how to generate valid parameters and any exceptions thrown while doing so
      // are most likely on us. However, if this happens too often, Autofuzz got stuck and we should
      // let the user know.
      executionsSinceLastInvocation++;
      if (executionsSinceLastInvocation >= MAX_EXECUTIONS_WITHOUT_INVOCATION) {
        Log.error(
            String.format(
                "Failed to generate valid arguments to '%s' in %d attempts; giving up",
                methodReference, executionsSinceLastInvocation));
        System.exit(1);
      } else if (executionsSinceLastInvocation == MAX_EXECUTIONS_WITHOUT_INVOCATION / 2) {
        // The application under test might perform classpath modifications or create classes
        // dynamically that implement interfaces or extend abstract classes. Rescanning the
        // classpath might help with constructing objects.
        Meta.rescanClasspath();
      }
    } catch (AutofuzzInvocationException e) {
      executionsSinceLastInvocation = 0;
      Throwable cause = e.getCause();
      Class<?> causeClass = cause.getClass();
      // Do not report exceptions declared to be thrown by the method under test.
      for (Class<?> declaredThrow :
          throwsDeclarations.getOrDefault(targetExecutable, new Class[0])) {
        if (declaredThrow.isAssignableFrom(causeClass)) {
          return;
        }
      }

      if (ignoredExceptionMatchers.stream().anyMatch(m -> m.matches(causeClass.getName()))) {
        return;
      }
      cleanStackTraces(cause);
      throw cause;
    } catch (Throwable t) {
      Log.error("Unexpected exception encountered during autofuzz", t);
      System.exit(1);
    } finally {
      if (returnValue instanceof Closeable) {
        ((Closeable) returnValue).close();
      }
    }
  }

  // Removes all stack trace elements that live in the Java reflection packages or the autofuzz
  // package from the bottom of all stack frames.
  private static void cleanStackTraces(Throwable t) {
    Throwable cause = t;
    while (cause != null) {
      StackTraceElement[] elements = cause.getStackTrace();
      int firstInterestingPos;
      for (firstInterestingPos = elements.length - 1;
          firstInterestingPos > 0;
          firstInterestingPos--) {
        String className = elements[firstInterestingPos].getClassName();
        if (!className.startsWith("com.code_intelligence.jazzer.autofuzz.")
            && !className.startsWith("java.lang.reflect.")
            && !className.startsWith("jdk.internal.reflect.")) {
          break;
        }
      }
      cause.setStackTrace(Arrays.copyOfRange(elements, 0, firstInterestingPos + 1));
      cause = cause.getCause();
    }
  }
}
