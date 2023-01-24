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

package com.code_intelligence.jazzer.driver;

import static java.lang.System.exit;
import static java.util.stream.Collectors.toList;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.driver.FuzzTargetHolder.FuzzTarget;
import com.code_intelligence.jazzer.utils.Log;
import com.code_intelligence.jazzer.utils.ManifestUtils;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.stream.Stream;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

class FuzzTargetFinder {
  private static final String FUZZ_TEST_ANNOTATION_CLASS =
      "com.code_intelligence.jazzer.junit.FuzzTest";
  private static final String FUZZ_TEST_ANNOTATION_DESCRIPTOR =
      "L" + FUZZ_TEST_ANNOTATION_CLASS.replace('.', '/') + ";";
  private static final String FUZZER_TEST_ONE_INPUT = "fuzzerTestOneInput";
  private static final String FUZZER_INITIALIZE = "fuzzerInitialize";
  private static final String FUZZER_TEAR_DOWN = "fuzzerTearDown";

  static String findFuzzTargetClassName() {
    if (!Opt.targetClass.isEmpty()) {
      return Opt.targetClass;
    }
    return ManifestUtils.detectFuzzTargetClass();
  }

  /**
   * @throws IllegalArgumentException if the fuzz target method is invalid or couldn't be found
   * @param targetClassName name of the fuzz target class
   * @return a {@link FuzzTarget}
   */
  static FuzzTarget findFuzzTarget(String targetClassName) {
    Class<?> fuzzTargetClass;
    try {
      fuzzTargetClass = Class.forName(targetClassName);
    } catch (ClassNotFoundException e) {
      Log.error(String.format(
          "'%s' not found on classpath:%n%n%s%n%nAll required classes must be on the classpath specified via --cp.",
          targetClassName, System.getProperty("java.class.path")));
      exit(1);
      throw new IllegalStateException("Not reached");
    }

    return findFuzzTargetByAnnotation(fuzzTargetClass)
        .orElseGet(() -> findFuzzTargetByMethodName(fuzzTargetClass));
  }

  // Finds and validates methods annotated with @FuzzTest.
  private static Optional<FuzzTarget> findFuzzTargetByAnnotation(Class<?> clazz) {
    List<Method> annotatedMethods = findFuzzTests(clazz);
    if (annotatedMethods.isEmpty()) {
      return Optional.empty();
    }

    Method method;
    if (annotatedMethods.size() > 1) {
      if (Opt.targetMethod.isEmpty()) {
        throw new IllegalArgumentException(String.format(
            "%s contains multiple methods annotated with @FuzzTest, but --target_method hasn't been specified",
            clazz.getName()));
      }
      List<Method> targetMethods = annotatedMethods.stream()
                                       .filter(m -> Opt.targetMethod.equals(m.getName()))
                                       .collect(toList());
      if (targetMethods.isEmpty()) {
        throw new IllegalArgumentException(
            String.format("%s contains no method called '%s' that is annotated with @FuzzTest",
                clazz.getName(), Opt.targetMethod));
      }
      if (targetMethods.size() > 1) {
        throw new IllegalArgumentException(String.format(
            "%s contains multiple methods called '%s' that are annotated with @FuzzTest - this is currently not supported",
            clazz.getName(), Opt.targetMethod));
      }
      method = targetMethods.get(0);
    } else {
      method = annotatedMethods.get(0);
    }

    // The following checks ensure compatibility with the JUnit concept of a test class and test
    // method.
    // https://junit.org/junit5/docs/5.9.0/user-guide/#writing-tests-definitions
    if (Modifier.isPrivate(method.getModifiers())) {
      throw new IllegalArgumentException(
          String.format("Methods annotated with @FuzzTest must not be private, got %s in %s",
              method.getName(), clazz.getName()));
    }
    if (Modifier.isStatic(method.getModifiers())) {
      throw new IllegalArgumentException(
          String.format("Methods annotated with @FuzzTest must not be static, got %s in %s",
              method.getName(), clazz.getName()));
    }
    if (method.getParameterCount() > 1) {
      throw new IllegalArgumentException(String.format(
          "Methods annotated with @FuzzTest must take a single parameter, got %d for %s in %s",
          method.getParameterCount(), method.getName(), clazz.getName()));
    }

    Class<?> parameter = method.getParameterTypes()[0];
    if (parameter != byte[].class && parameter != FuzzedDataProvider.class) {
      throw new IllegalArgumentException(String.format(
          "Methods annotated with @FuzzTest must take a single byte[] or FuzzedDataProvider parameter, got %s for %s in %s",
          parameter.getName(), method.getName(), clazz.getName()));
    }

    // TODO: All of this code should go away once we use JUnit's launcher to run @FuzzTests.
    // Use the default constructor to initialize a test class instance.
    if (clazz.getDeclaredConstructors().length != 1) {
      throw new IllegalArgumentException(String.format(
          "Classes containing a method annotated with @FuzzTest must declare exactly one constructor, got multiple in %s",
          clazz.getName()));
    }
    Constructor<?> constructor = clazz.getDeclaredConstructors()[0];
    // JUnit 5 supports injected constructor parameters, but we don't.
    if (constructor.getParameterCount() > 0) {
      throw new IllegalArgumentException(String.format(
          "The constructor of a class containing a method annotated with @FuzzTest must take no parameters, got a non-zero number in %s",
          clazz.getName()));
    }
    constructor.setAccessible(true);

    // TODO: If it should become necessary, implement support for @AfterAll/@AfterEach as
    //  JUnit-idiomatic replacements for fuzzerTearDown.
    return Optional.of(new FuzzTarget(method, constructor::newInstance, Optional.empty()));
  }

  // Finds the traditional static fuzzerTestOneInput fuzz target method.
  private static FuzzTarget findFuzzTargetByMethodName(Class<?> clazz) {
    Optional<Method> bytesFuzzTarget =
        targetPublicStaticMethod(clazz, FUZZER_TEST_ONE_INPUT, byte[].class);
    Optional<Method> dataFuzzTarget =
        targetPublicStaticMethod(clazz, FUZZER_TEST_ONE_INPUT, FuzzedDataProvider.class);
    if (bytesFuzzTarget.isPresent() == dataFuzzTarget.isPresent()) {
      throw new IllegalArgumentException(String.format(
          "%s must define exactly one of the following two functions:%n"
              + "public static void fuzzerTestOneInput(byte[] ...)%n"
              + "public static void fuzzerTestOneInput(FuzzedDataProvider ...)%n"
              + "Note: Fuzz targets returning boolean are no longer supported; exceptions should be thrown instead of returning true.",
          clazz.getName()));
    }

    Callable<Object> initialize =
        Stream
            .of(targetPublicStaticMethod(clazz, FUZZER_INITIALIZE, String[].class)
                    .map(init -> (Callable<Object>) () -> {
                      init.invoke(null, (Object) Opt.targetArgs.toArray(new String[] {}));
                      return null;
                    }),
                targetPublicStaticMethod(clazz, FUZZER_INITIALIZE)
                    .map(init -> (Callable<Object>) () -> {
                      init.invoke(null);
                      return null;
                    }))
            .filter(Optional::isPresent)
            .map(Optional::get)
            .findFirst()
            .orElse(() -> null);

    return new FuzzTarget(dataFuzzTarget.orElseGet(bytesFuzzTarget::get), initialize,
        targetPublicStaticMethod(clazz, FUZZER_TEAR_DOWN));
  }

  private static Optional<Method> targetPublicStaticMethod(
      Class<?> clazz, String name, Class<?>... parameterTypes) {
    try {
      Method method = clazz.getMethod(name, parameterTypes);
      if (!Modifier.isStatic(method.getModifiers()) || !Modifier.isPublic(method.getModifiers())) {
        return Optional.empty();
      }
      return Optional.of(method);
    } catch (NoSuchMethodException e) {
      return Optional.empty();
    }
  }

  // Returns a list of all methods annotated with @FuzzTest without requiring @FuzzTest to be on the
  // class path.
  private static List<Method> findFuzzTests(Class<?> clazz) {
    // Stores pairs of the form (method name, method descriptor).
    HashSet<Map.Entry<String, String>> annotatedMethods = new HashSet<>();
    // If an annotation is not on the classpath, it is silently ignored when the annotated element
    // is loaded. We thus need to load and parse the class file ourselves.
    try (InputStream stream = FuzzTargetFinder.class.getResourceAsStream(
             "/" + clazz.getName().replace('.', '/') + ".class")) {
      ClassReader reader = new ClassReader(stream);
      reader.accept(new ClassVisitor(Opcodes.ASM9) {
        @Override
        public MethodVisitor visitMethod(int access, String methodName, String descriptor,
            String signature, String[] exceptions) {
          return new MethodVisitor(Opcodes.ASM9) {
            @Override
            public AnnotationVisitor visitAnnotation(String annotationName, boolean visible) {
              if (annotationName.equals(FUZZ_TEST_ANNOTATION_DESCRIPTOR)) {
                annotatedMethods.add(new AbstractMap.SimpleEntry<>(methodName, descriptor));
              }
              return null;
            }
          };
        }
      }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    } catch (IOException e) {
      e.printStackTrace();
      // Fall back to using the provided Class object to find annotated methods - this requires
      // @FuzzTest to be on the classpath.
      return Arrays.stream(clazz.getDeclaredMethods())
          .filter(method
              -> Arrays.stream(method.getAnnotations())
                     .anyMatch(annotation
                         -> annotation.annotationType().getName().equals(
                             FUZZ_TEST_ANNOTATION_CLASS)))
          .collect(toList());
    }
    return Arrays.stream(clazz.getDeclaredMethods())
        .filter(method
            -> annotatedMethods.contains(
                new AbstractMap.SimpleEntry<>(method.getName(), Type.getMethodDescriptor(method))))
        .collect(toList());
  }
}
