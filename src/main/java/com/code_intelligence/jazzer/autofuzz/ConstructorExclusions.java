/*
 * Copyright 2026 Code Intelligence GmbH
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

import com.code_intelligence.jazzer.utils.Utils;
import java.lang.reflect.Constructor;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

final class ConstructorExclusions {
  private static final String CONSTRUCTOR_REFERENCE = "::new";
  private static final ConstructorExclusions EMPTY =
      new ConstructorExclusions(Collections.emptySet());

  static ConstructorExclusions empty() {
    return EMPTY;
  }

  static ConstructorExclusions from(
      List<String> constructorReferences, AccessibleObjectLookup lookup) {
    return constructorReferences.isEmpty()
        ? EMPTY
        : new ConstructorExclusions(
            constructorReferences.stream()
                .map(String::trim)
                .filter(reference -> !reference.isEmpty())
                .map(reference -> resolveConstructorReference(reference, lookup))
                .collect(
                    Collectors.collectingAndThen(
                        Collectors.toCollection(LinkedHashSet::new),
                        Collections::unmodifiableSet)));
  }

  private final Set<String> excludedConstructorReferences;

  private ConstructorExclusions(Set<String> excludedConstructorReferences) {
    this.excludedConstructorReferences = excludedConstructorReferences;
  }

  boolean isExcluded(Constructor<?> constructor) {
    return !excludedConstructorReferences.isEmpty()
        && excludedConstructorReferences.contains(toConstructorReference(constructor));
  }

  private static String toConstructorReference(Constructor<?> constructor) {
    return constructor.getDeclaringClass().getName()
        + CONSTRUCTOR_REFERENCE
        + Utils.getReadableDescriptor(constructor);
  }

  private static String resolveConstructorReference(
      String reference, AccessibleObjectLookup lookup) {
    int separator = reference.indexOf(CONSTRUCTOR_REFERENCE);
    if (separator <= 0 || separator != reference.lastIndexOf(CONSTRUCTOR_REFERENCE)) {
      throw invalidConstructorReference(reference);
    }

    String className = reference.substring(0, separator);
    String descriptor = reference.substring(separator + CONSTRUCTOR_REFERENCE.length());
    if (!descriptor.startsWith("(")
        || !descriptor.endsWith(")")
        || descriptor.indexOf(')') != descriptor.length() - 1) {
      throw invalidConstructorReference(reference);
    }

    Class<?> clazz = loadClass(reference, className);
    Constructor<?>[] constructors = lookup.getAccessibleConstructors(clazz);
    List<Constructor<?>> matchingConstructors =
        Arrays.stream(constructors)
            .filter(constructor -> Utils.getReadableDescriptor(constructor).equals(descriptor))
            .collect(Collectors.toList());

    if (matchingConstructors.size() == 1) {
      return toConstructorReference(matchingConstructors.get(0));
    }
    throw noMatchingConstructor(reference, clazz, constructors);
  }

  private static Class<?> loadClass(String reference, String className) {
    try {
      return Class.forName(className, false, ClassLoader.getSystemClassLoader());
    } catch (ClassNotFoundException e) {
      throw classNotFound(reference, className, e);
    }
  }

  private static IllegalArgumentException invalidConstructorReference(String reference) {
    return new IllegalArgumentException(
        String.format(
            "Invalid Autofuzz constructor exclude '%s'; expected exact constructor reference like"
                + " 'com.example.Dangerous::new(int,java.util.Random)'",
            reference));
  }

  private static IllegalArgumentException classNotFound(
      String reference, String className, ClassNotFoundException cause) {
    return new IllegalArgumentException(
        String.format(
            "Invalid Autofuzz constructor exclude '%s'; class '%s' could not be found",
            reference, className),
        cause);
  }

  private static IllegalArgumentException noMatchingConstructor(
      String reference, Class<?> clazz, Constructor<?>[] constructors) {
    return new IllegalArgumentException(
        String.format(
            "Invalid Autofuzz constructor exclude '%s'; no accessible constructor with this"
                + " descriptor found in %s.%nAccessible constructors:%n%s",
            reference, clazz.getName(), formatConstructorReferences(constructors)));
  }

  private static String formatConstructorReferences(Constructor<?>[] constructors) {
    if (constructors.length == 0) {
      return "<none>";
    }
    return Arrays.stream(constructors)
        .map(ConstructorExclusions::toConstructorReference)
        .collect(Collectors.joining(System.lineSeparator()));
  }
}
