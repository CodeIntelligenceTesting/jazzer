/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.lang;

import static com.code_intelligence.jazzer.mutation.support.TypeSupport.isPrimitive;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.notNull;
import static java.util.Arrays.stream;

import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedType;
import java.util.Optional;
import java.util.function.Predicate;

final class NullableMutatorFactory extends MutatorFactory {
  private static boolean isNotNullAnnotation(Annotation annotation) {
    // There are many NotNull annotations in the wild (including our own) and we want to recognize
    // them all.
    return annotation.annotationType().getSimpleName().equals("NotNull");
  }

  @Override
  public Optional<SerializingMutator<?>> tryCreate(AnnotatedType type, MutatorFactory factory) {
    if (isPrimitive(type)
        || stream(type.getAnnotations()).anyMatch(NullableMutatorFactory::isNotNullAnnotation)) {
      return Optional.empty();
    }
    return factory.tryCreate(notNull(type), factory).map(NullableMutator::new);
  }

  private static final class NullableMutator<T> extends SerializingMutator<T> {
    private static final int INVERSE_FREQUENCY_NULL = 100;

    private final SerializingMutator<T> mutator;

    NullableMutator(SerializingMutator<T> mutator) {
      this.mutator = mutator;
    }

    @Override
    public T read(DataInputStream in) throws IOException {
      if (in.readBoolean()) {
        return mutator.read(in);
      } else {
        return null;
      }
    }

    @Override
    public void write(T value, DataOutputStream out) throws IOException {
      out.writeBoolean(value != null);
      if (value != null) {
        mutator.write(value, out);
      }
    }

    @Override
    public T init(PseudoRandom prng) {
      if (prng.trueInOneOutOf(INVERSE_FREQUENCY_NULL)) {
        return null;
      } else {
        return mutator.init(prng);
      }
    }

    @Override
    public T mutate(T value, PseudoRandom prng) {
      if (value == null) {
        return mutator.init(prng);
      } else if (prng.trueInOneOutOf(INVERSE_FREQUENCY_NULL)) {
        return null;
      } else {
        return mutator.mutate(value, prng);
      }
    }

    @Override
    public T crossOver(T value, T otherValue, PseudoRandom prng) {
      // Prefer to cross over actual values and only return null if
      // both are null or at INVERSE_FREQUENCY_NULL probability.
      if (value != null && otherValue != null) {
        return mutator.crossOver(value, otherValue, prng);
      } else if (value == null && otherValue == null) {
        return null;
      } else if (prng.trueInOneOutOf(INVERSE_FREQUENCY_NULL)) {
        return null;
      } else {
        return value != null ? value : otherValue;
      }
    }

    @Override
    protected boolean computeHasFixedSize() {
      return mutator.hasFixedSize();
    }

    @Override
    public T detach(T value) {
      if (value == null) {
        return null;
      } else {
        return mutator.detach(value);
      }
    }

    @Override
    public String toDebugString(Predicate<Debuggable> isInCycle) {
      return "Nullable<" + mutator.toDebugString(isInCycle) + ">";
    }
  }
}
