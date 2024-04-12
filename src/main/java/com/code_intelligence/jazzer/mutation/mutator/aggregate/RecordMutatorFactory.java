/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.aggregate;

import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asSubclassOrEmpty;
import static java.util.Arrays.stream;

import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.util.Optional;

final class RecordMutatorFactory implements MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    return asSubclassOrEmpty(type, Record.class)
        .flatMap(
            clazz -> {
              try {
                return AggregatesHelper.ofImmutable(
                    factory,
                    type,
                    getCanonicalConstructor(clazz),
                    stream(clazz.getRecordComponents())
                        .map(RecordComponent::getAccessor)
                        .toArray(Method[]::new));
              } catch (NoSuchMethodException e) {
                throw new IllegalStateException(e);
              }
            });
  }

  private <T extends Record> Constructor<T> getCanonicalConstructor(Class<T> clazz)
      throws NoSuchMethodException {
    Class<?>[] paramTypes =
        stream(clazz.getRecordComponents()).map(RecordComponent::getType).toArray(Class<?>[]::new);
    return clazz.getDeclaredConstructor(paramTypes);
  }
}
