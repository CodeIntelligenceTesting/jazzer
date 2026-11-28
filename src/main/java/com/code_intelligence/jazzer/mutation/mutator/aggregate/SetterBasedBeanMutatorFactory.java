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

package com.code_intelligence.jazzer.mutation.mutator.aggregate;

import static com.code_intelligence.jazzer.mutation.mutator.aggregate.BeanSupport.*;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asSubclassOrEmpty;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toSet;

import com.code_intelligence.jazzer.mutation.annotation.IgnoreGetters;
import com.code_intelligence.jazzer.mutation.annotation.IgnoreProperties;
import com.code_intelligence.jazzer.mutation.annotation.IgnoreSetters;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.WildcardType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

final class SetterBasedBeanMutatorFactory implements MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    Set<String> ignoredProperties =
        extractIgnoredValues(type, IgnoreProperties.class, IgnoreProperties::value);
    Set<Class<?>> ignoredTypes =
        extractIgnoredValues(type, IgnoreProperties.class, IgnoreProperties::types);
    Set<String> ignoredGetters =
        extractIgnoredValues(type, IgnoreGetters.class, IgnoreGetters::value);
    Set<String> ignoredSetters =
        extractIgnoredValues(type, IgnoreSetters.class, IgnoreSetters::value);

    return asSubclassOrEmpty(type, Object.class)
        .filter(BeanSupport::isConcreteClass)
        .flatMap(BeanSupport::findDefaultConstructor)
        .flatMap(
            constructor -> {
              Class<?> clazz = constructor.getDeclaringClass();
              Map<String, Method> gettersByPropertyName = findGettersByPropertyName(clazz);
              List<Method> setters = new ArrayList<>();
              List<Method> getters = new ArrayList<>();
              for (Method setter :
                  findMethods(clazz, BeanSupport::isSetter).toArray(Method[]::new)) {
                String propertyName = toPropertyName(setter);
                if (ignoredSetters.contains(setter.getName())
                    || ignoredProperties.contains(propertyName)
                    || containsIgnoredType(resolveParameterTypes(setter, type)[0], ignoredTypes)) {
                  continue;
                }
                Method getter = gettersByPropertyName.get(propertyName);
                if (getter == null) {
                  // A Java bean can have additional getters corresponding to computed properties,
                  // but we require that all non-ignored setters have a corresponding getter.
                  return Optional.empty();
                }
                if (ignoredGetters.contains(getter.getName())
                    || containsIgnoredType(resolveReturnType(getter, type), ignoredTypes)) {
                  continue;
                }
                setters.add(setter);
                getters.add(getter);
              }

              // Classes with a default constructor but without (non-ignored) setters are handled by
              // the CachedConstructorMutator.
              if (setters.isEmpty()) {
                return Optional.empty();
              }

              Method[] setterArray = setters.toArray(Method[]::new);
              Method[] getterArray = getters.toArray(Method[]::new);
              if (!matchingReturnTypes(
                  getterArray,
                  type,
                  stream(setterArray)
                      .map(setter -> resolveParameterTypes(setter, type)[0])
                      .toArray(Type[]::new))) {
                return Optional.empty();
              }
              return AggregatesHelper.createMutator(
                  factory, type, constructor, getterArray, setterArray);
            });
  }

  private static <A extends Annotation, T> Set<T> extractIgnoredValues(
      AnnotatedType type, Class<A> annotationClass, Function<A, T[]> extractor) {
    return stream(type.getAnnotations())
        .filter(annotationClass::isInstance)
        .map(annotationClass::cast)
        .map(extractor)
        .flatMap(Arrays::stream)
        .collect(toSet());
  }

  private static boolean containsIgnoredType(Type type, Set<Class<?>> ignoredTypes) {
    if (ignoredTypes.isEmpty()) {
      return false;
    }
    if (type instanceof Class<?>) {
      Class<?> clazz = (Class<?>) type;
      if (ignoredTypes.stream().anyMatch(ignored -> ignored.isAssignableFrom(clazz))) {
        return true;
      }
      return clazz.isArray() && containsIgnoredType(clazz.getComponentType(), ignoredTypes);
    } else if (type instanceof ParameterizedType) {
      ParameterizedType parameterizedType = (ParameterizedType) type;
      if (containsIgnoredType(parameterizedType.getRawType(), ignoredTypes)) {
        return true;
      }
      return stream(parameterizedType.getActualTypeArguments())
          .anyMatch(arg -> containsIgnoredType(arg, ignoredTypes));
    } else if (type instanceof GenericArrayType) {
      return containsIgnoredType(((GenericArrayType) type).getGenericComponentType(), ignoredTypes);
    } else if (type instanceof WildcardType) {
      WildcardType wildcardType = (WildcardType) type;
      return stream(wildcardType.getUpperBounds())
              .anyMatch(bound -> containsIgnoredType(bound, ignoredTypes))
          || stream(wildcardType.getLowerBounds())
              .anyMatch(bound -> containsIgnoredType(bound, ignoredTypes));
    }
    return false;
  }
}
