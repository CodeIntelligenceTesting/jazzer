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

package com.code_intelligence.jazzer.mutation.mutator.lang;

import static com.code_intelligence.jazzer.mutation.support.TypeSupport.isPrimitive;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.notNull;
import static java.util.Arrays.stream;

import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
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

final class NullableMutatorFactory implements MutatorFactory {
  private static boolean isNotNullAnnotation(Annotation annotation) {
    // There are many NotNull annotations in the wild (including our own) and we want to recognize
    // them all.
    return annotation.annotationType().getSimpleName().equals("NotNull");
  }

  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    if (isPrimitive(type)
        || stream(type.getAnnotations()).anyMatch(NullableMutatorFactory::isNotNullAnnotation)) {
      return Optional.empty();
    }
    return factory.tryCreate(notNull(type)).map(NullableMutator::new);
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
      if (mutator.requiresRecursionBreaking() || prng.trueInOneOutOf(INVERSE_FREQUENCY_NULL)) {
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
