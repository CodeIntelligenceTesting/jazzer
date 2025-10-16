/*
 * Copyright 2025 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.code_intelligence.jazzer.mutation.support;

import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;

import com.code_intelligence.jazzer.mutation.annotation.DictionaryProvider;
import com.code_intelligence.jazzer.mutation.runtime.MutatorRuntime;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class DictionaryProviderSupport {

  /**
   * Extract inverse probability of the very last {@code DictionaryProvider} annotation on the given
   * type.
   */
  public static int extractLastInvProbability(AnnotatedType type) {
    DictionaryProvider[] dictObj = type.getAnnotationsByType(DictionaryProvider.class);
    int pInv =
        Arrays.stream(dictObj)
            .map(DictionaryProvider::pInv)
            .reduce((first, second) -> second)
            .orElseThrow(() -> new IllegalStateException("No DictionaryProvider annotation found"));
    require(pInv >= 2, "@DictionaryProvider.pInv must be at least 2");
    return pInv;
  }

  /** Extract the provider streams using MutatorRuntime */
  public static Optional<Stream<?>> extractProviderStreams(
      MutatorRuntime runtime, AnnotatedType type) {
    DictionaryProvider[] providers = type.getAnnotationsByType(DictionaryProvider.class);
    if (providers.length == 0) {
      return Optional.empty();
    }
    HashSet<String> providerMethodNames =
        Arrays.stream(providers)
            .map(DictionaryProvider::value)
            .flatMap(Arrays::stream)
            .filter(name -> !name.isEmpty())
            .collect(Collectors.toCollection(HashSet::new));
    if (providerMethodNames.isEmpty()) {
      return Optional.empty();
    }
    Map<String, Method> fuzzTestMethods =
        Arrays.stream(runtime.fuzzTestMethod.getDeclaringClass().getDeclaredMethods())
            .filter(m -> m.getParameterCount() == 0)
            .filter(m -> m.getReturnType().equals(Stream.class))
            .filter(
                m ->
                    (m.getModifiers()
                            & (java.lang.reflect.Modifier.PUBLIC
                                | java.lang.reflect.Modifier.STATIC))
                        == (java.lang.reflect.Modifier.PUBLIC | java.lang.reflect.Modifier.STATIC))
            .collect(Collectors.toMap(Method::getName, m -> m));

    return Optional.ofNullable(
        providerMethodNames.stream()
            .flatMap(
                name -> {
                  Method m = fuzzTestMethods.get(name);
                  if (m == null) {
                    throw new IllegalStateException(
                        "No method named "
                            + name
                            + " with signature 'public static Stream<?> "
                            + name
                            + "()' found in class "
                            + runtime.fuzzTestMethod.getDeclaringClass().getName());
                  }
                  try {
                    return (Stream<?>) m.invoke(null);
                  } catch (IllegalAccessException e) {
                    throw new RuntimeException(e);
                  } catch (InvocationTargetException e) {
                    throw new RuntimeException(e);
                  }
                }));
  }
}
