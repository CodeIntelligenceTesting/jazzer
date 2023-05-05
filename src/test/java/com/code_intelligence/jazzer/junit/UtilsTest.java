// Copyright 2022 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.junit;

import static com.code_intelligence.jazzer.junit.Utils.durationStringToSeconds;
import static com.code_intelligence.jazzer.junit.Utils.getMarkedArguments;
import static com.code_intelligence.jazzer.junit.Utils.getMarkedInstance;
import static com.code_intelligence.jazzer.junit.Utils.isMarkedInstance;
import static com.code_intelligence.jazzer.junit.Utils.isMarkedInvocation;
import static com.google.common.truth.Truth.assertThat;
import static java.util.Arrays.stream;
import static java.util.Collections.singletonList;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.lang.reflect.Method;
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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

public class UtilsTest implements InvocationInterceptor {
  @Test
  void testDurationStringToSeconds() {
    assertThat(durationStringToSeconds("1m")).isEqualTo(60);
    assertThat(durationStringToSeconds("1min")).isEqualTo(60);
    assertThat(durationStringToSeconds("1h")).isEqualTo(60 * 60);
    assertThat(durationStringToSeconds("1h   2m 30s")).isEqualTo(60 * 60 + 2 * 60 + 30);
    assertThat(durationStringToSeconds("1hr2min30sec")).isEqualTo(60 * 60 + 2 * 60 + 30);
    assertThat(durationStringToSeconds("1h2m30s")).isEqualTo(60 * 60 + 2 * 60 + 30);
  }

  @ValueSource(classes = {int.class, Class.class, Object.class, String.class, HashMap.class,
                   Map.class, int[].class, int[][].class, AbstractMap.class, AbstractList.class})
  @ParameterizedTest
  void
  testMarkedInstances(Class<?> clazz) {
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
        arguments("baz", 1, new LinkedHashMap<>(), Arrays.asList(5, 7), String.class, new int[0]),
        getMarkedArguments(testMethod, "some other name"));
  }

  @MethodSource("testWithMarkedNamedParametersSource")
  @ExtendWith(UtilsTest.class)
  @ParameterizedTest
  void testWithMarkedNamedParameters(String str, int num, AbstractMap<String, String> map,
      List<Integer> list, Class<?> clazz, int[] array) {}

  boolean argumentsExpectedToBeMarked = false;

  @Override
  public void interceptTestTemplateMethod(Invocation<Void> invocation,
      ReflectiveInvocationContext<Method> invocationContext, ExtensionContext extensionContext)
      throws Throwable {
    assertThat(isMarkedInvocation(invocationContext)).isEqualTo(argumentsExpectedToBeMarked);
    argumentsExpectedToBeMarked = !argumentsExpectedToBeMarked;
    invocation.proceed();
  }
}
