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
import com.code_intelligence.jazzer.mutation.runtime.MutationRuntime;
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
   * Extract inverse probability of the very first {@code DictionaryProvider} annotation on the
   * given type. The {@code @DictionaryProvider} annotation directly on the type is preferred; if
   * there is none, the first one appended because of {@code PropertyConstraint.RECURSIVE} is used.
   * Any further {@code @DictionaryProvider} annotations appended later to this type because of
   * {@code PropertyConstraint.RECURSIVE}, are ignored. Callers should ensure that at least one
   * {@code @DictionaryProvider} annotation is present on the type.
   */
  public static int extractFirstInvProbability(AnnotatedType type) {
    // If there are several @DictionaryProvider annotations on the type, this will take the most
    // immediate one, because @DictionaryProvider is not repeatable.
    DictionaryProvider[] dictObj = type.getAnnotationsByType(DictionaryProvider.class);
    if (dictObj.length == 0) {
      // If we are here, it's a bug in the caller.
      throw new IllegalStateException("Expected to find @DictionaryProvider, but found none.");
    }
    int pInv = dictObj[0].pInv();
    require(pInv >= 2, "@DictionaryProvider.pInv must be at least 2");
    return pInv;
  }

  /** Extract the provider streams using MutatorRuntime */
  public static Optional<Stream<?>> extractRawValues(AnnotatedType type) {
    DictionaryProvider[] providers =
        Arrays.stream(type.getAnnotations())
            .filter(a -> a instanceof DictionaryProvider)
            .map(a -> (DictionaryProvider) a)
            .toArray(DictionaryProvider[]::new);
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
        Arrays.stream(MutationRuntime.fuzzTestMethod.getDeclaringClass().getDeclaredMethods())
            .filter(m -> m.getParameterCount() == 0)
            .filter(m -> m.getReturnType().equals(Stream.class))
            .filter(
                m ->
                    (m.getModifiers() & java.lang.reflect.Modifier.STATIC)
                        == java.lang.reflect.Modifier.STATIC)
            .collect(Collectors.toMap(Method::getName, m -> m));
    return Optional.ofNullable(
        providerMethodNames.stream()
            .flatMap(
                name -> {
                  Method m = fuzzTestMethods.get(name);
                  if (m == null) {
                    throw new IllegalStateException(
                        "Found no static supplier method 'Stream<?> "
                            + name
                            + "()' in class "
                            + MutationRuntime.fuzzTestMethod.getDeclaringClass().getName());
                  }
                  try {
                    m.setAccessible(true);
                    return (Stream<?>) m.invoke(null);
                  } catch (IllegalAccessException e) {
                    throw new IllegalStateException("Cannot access method " + name, e);
                  } catch (InvocationTargetException e) {
                    throw new RuntimeException(
                        "Supplier method " + name + " threw an exception", e.getCause());
                  }
                })
            .distinct());
  }
}
