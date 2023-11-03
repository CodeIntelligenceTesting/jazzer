package com.code_intelligence.jazzer.mutation.mutator.aggregate;

import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.TypeSupport;

import java.lang.reflect.AnnotatedType;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.util.Optional;

import static com.code_intelligence.jazzer.mutation.mutator.aggregate.AggregateMutator.ofImmutable;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asSubclassOrEmpty;
import static java.util.Arrays.stream;

final class RecordMutatorFactory extends MutatorFactory {
  @Override
  @SuppressWarnings("Immutable")
  public Optional<SerializingMutator<?>> tryCreate(AnnotatedType type, MutatorFactory factory) {
    return asSubclassOrEmpty(type, Record.class)
        .flatMap(
            clazz -> {
              try {
                return ofImmutable(
                    factory,
                    getCanonicalConstructor(clazz),
                    stream(clazz.getRecordComponents())
                        .map(RecordComponent::getAccessor)
                        .toArray(Method[]::new));
              } catch (NoSuchMethodException e) {
                throw new IllegalStateException(e);
              }
            });
  }

  private static <T extends Record> Constructor<T> getCanonicalConstructor(Class<T> clazz)
      throws NoSuchMethodException {
    Class<?>[] paramTypes =
        stream(clazz.getRecordComponents()).map(RecordComponent::getType).toArray(Class<?>[]::new);
    return clazz.getDeclaredConstructor(paramTypes);
  }
}
