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

import static com.code_intelligence.jazzer.junit.Utils.durationStringToSeconds;
import static com.code_intelligence.jazzer.junit.Utils.getMarkedArguments;
import static com.code_intelligence.jazzer.junit.Utils.getMarkedInstance;
import static com.code_intelligence.jazzer.junit.Utils.isMarkedInstance;
import static com.code_intelligence.jazzer.junit.Utils.isMarkedInvocation;
import static com.code_intelligence.jazzer.junit.Utils.parseJUnitTimeoutValueToSeconds;
import static com.google.common.truth.Truth.assertThat;
import static java.nio.file.Files.createDirectories;
import static java.nio.file.Files.createFile;
import static java.util.Arrays.asList;
import static java.util.Arrays.stream;
import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.joining;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.AbstractList;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.InvocationInterceptor;
import org.junit.jupiter.api.extension.ReflectiveInvocationContext;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

public class UtilsTest implements InvocationInterceptor {
  @TempDir Path temp;

  @Test
  void testDurationStringToSeconds() {
    assertThat(durationStringToSeconds("")).isEqualTo(0);
    assertThat(durationStringToSeconds("0s")).isEqualTo(0);
    assertThat(durationStringToSeconds("1m")).isEqualTo(60);
    assertThat(durationStringToSeconds("1min")).isEqualTo(60);
    assertThat(durationStringToSeconds("1h")).isEqualTo(60 * 60);
    assertThat(durationStringToSeconds("1h   2m 30s")).isEqualTo(60 * 60 + 2 * 60 + 30);
    assertThat(durationStringToSeconds("1hr2min30sec")).isEqualTo(60 * 60 + 2 * 60 + 30);
    assertThat(durationStringToSeconds("1h2m30s")).isEqualTo(60 * 60 + 2 * 60 + 30);
  }

  @Test
  void testParseJUnitTimeoutValueToSeconds() {
    assertThat(parseJUnitTimeoutValueToSeconds("5")).isEqualTo(5);
    assertThat(parseJUnitTimeoutValueToSeconds("5s")).isEqualTo(5);
    assertThat(parseJUnitTimeoutValueToSeconds("50 s")).isEqualTo(50);
    assertThat(parseJUnitTimeoutValueToSeconds("5m")).isEqualTo(300);
    assertThat(parseJUnitTimeoutValueToSeconds("5 m")).isEqualTo(300);
    assertThat(parseJUnitTimeoutValueToSeconds("5 ms")).isEqualTo(1);
    assertThrows(IllegalArgumentException.class, () -> parseJUnitTimeoutValueToSeconds("5 5"));
  }

  @ValueSource(
      classes = {
        int.class,
        Class.class,
        Object.class,
        String.class,
        HashMap.class,
        Map.class,
        int[].class,
        int[][].class,
        AbstractMap.class,
        AbstractList.class
      })
  @ParameterizedTest
  void testMarkedInstances(Class<?> clazz) {
    Object instance = getMarkedInstance(clazz);
    if (clazz == int.class) {
      assertThat(instance).isInstanceOf(Integer.class);
    } else {
      assertThat(instance).isInstanceOf(clazz);
    }
    assertThat(isMarkedInstance(instance)).isTrue();
    assertThat(getMarkedInstance(clazz)).isSameInstanceAs(instance);
  }

  static Stream<Arguments> testWithMarkedNamedParametersSource() {
    Method testMethod =
        stream(UtilsTest.class.getDeclaredMethods())
            .filter(method -> method.getName().equals("testWithMarkedNamedParameters"))
            .findFirst()
            .get();
    return Stream.of(
        arguments("foo", 0, new HashMap<>(), singletonList(5), UtilsTest.class, new int[] {1}),
        getMarkedArguments(testMethod, "some name"),
        arguments("baz", 1, new LinkedHashMap<>(), asList(5, 7), String.class, new int[0]),
        getMarkedArguments(testMethod, "some other name"));
  }

  @MethodSource("testWithMarkedNamedParametersSource")
  @ExtendWith(UtilsTest.class)
  @ParameterizedTest
  void testWithMarkedNamedParameters(
      String str,
      int num,
      AbstractMap<String, String> map,
      List<Integer> list,
      Class<?> clazz,
      int[] array) {}

  boolean argumentsExpectedToBeMarked = false;

  @Override
  public void interceptTestTemplateMethod(
      Invocation<Void> invocation,
      ReflectiveInvocationContext<Method> invocationContext,
      ExtensionContext extensionContext)
      throws Throwable {
    assertThat(isMarkedInvocation(invocationContext)).isEqualTo(argumentsExpectedToBeMarked);
    argumentsExpectedToBeMarked = !argumentsExpectedToBeMarked;
    invocation.proceed();
  }

  @Test
  public void testGetClassPathBasedInstrumentationFilter() throws IOException {
    Path firstDir = createDirectories(temp.resolve("first_dir"));
    Path orgExample = createDirectories(firstDir.resolve("org").resolve("example"));
    createFile(orgExample.resolve("Application.class"));

    Path nonExistentDir = temp.resolve("does not exist");

    Path secondDir = createDirectories(temp.resolve("second").resolve("dir"));
    createFile(secondDir.resolve("Root.class"));
    Path comExampleProject =
        createDirectories(secondDir.resolve("com").resolve("example").resolve("project"));
    createFile(comExampleProject.resolve("Main.class"));
    Path comExampleOtherProject =
        createDirectories(secondDir.resolve("com").resolve("example").resolve("other_project"));
    createFile(comExampleOtherProject.resolve("Lib.class"));

    Path emptyDir = createDirectories(temp.resolve("some").resolve("empty").resolve("dir"));

    Path firstJar = createFile(temp.resolve("first.jar"));
    Path secondJar = createFile(temp.resolve("second.jar"));

    assertThat(
            Utils.getClassPathBasedInstrumentationFilter(
                makeClassPath(firstDir, firstJar, nonExistentDir, secondDir, secondJar, emptyDir)))
        .hasValue(
            asList(
                "*", "com.example.other_project.**", "com.example.project.**", "org.example.**"));
  }

  @Test
  public void testGetClassPathBasedInstrumentationFilter_noDirs() throws IOException {
    Path firstJar = createFile(temp.resolve("first.jar"));
    Path secondJar = createFile(temp.resolve("second.jar"));

    assertThat(Utils.getClassPathBasedInstrumentationFilter(makeClassPath(firstJar, secondJar)))
        .isEmpty();
  }

  private static String makeClassPath(Path... paths) {
    return Arrays.stream(paths).map(Path::toString).collect(joining(File.pathSeparator));
  }
}
