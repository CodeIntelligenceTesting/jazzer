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

package com.code_intelligence.jazzer.mutation.mutator.lang;

import static java.lang.annotation.ElementType.TYPE_USE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.code_intelligence.jazzer.mutation.support.TypeSupport;
import com.code_intelligence.jazzer.mutation.support.ValuePoolRegistry;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import java.lang.reflect.AnnotatedType;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ValuePoolMutatorFactory implements MutatorFactory {
  /** Types annotated with this marker wil not be re-wrapped by this factory. */
  @Target({TYPE_USE})
  @Retention(RUNTIME)
  private @interface ValuePoolMarker {}

  public static final Annotation VALUE_POOL_MARKER =
      new TypeHolder<@ValuePoolMarker String>() {}.annotatedType()
          .getAnnotation(ValuePoolMarker.class);

  private final ValuePoolRegistry valuePoolRegistry;

  ValuePoolMutatorFactory(ValuePoolRegistry valuePoolRegistry) {
    this.valuePoolRegistry = valuePoolRegistry;
  }

  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    if (valuePoolRegistry == null || type.getAnnotation(ValuePoolMarker.class) != null) {
      return Optional.empty();
    }
    AnnotatedType markedType = TypeSupport.withExtraAnnotations(type, VALUE_POOL_MARKER);
    return factory
        .tryCreate(markedType)
        .map(mutator -> ValuePoolMutator.wrapIfValuesExist(markedType, mutator, valuePoolRegistry));
  }

  private static final class ValuePoolMutator<T> extends SerializingMutator<T> {
    private final SerializingMutator<T> mutator;
    private final List<T> userValues;
    private final double poolUsageProbability;

    ValuePoolMutator(
        SerializingMutator<T> mutator, List<T> userValues, double poolUsageProbability) {
      this.mutator = mutator;
      this.userValues = userValues;
      this.poolUsageProbability = poolUsageProbability;
    }

    @SuppressWarnings("unchecked")
    static <T> SerializingMutator<T> wrapIfValuesExist(
        AnnotatedType type, SerializingMutator<T> mutator, ValuePoolRegistry valuePoolRegistry) {

      if (valuePoolRegistry == null) {
        return mutator;
      }

      Optional<Stream<?>> rawUserValues = valuePoolRegistry.extractRawValues(type);
      if (!rawUserValues.isPresent()) {
        return mutator;
      }

      List<T> userValues =
          rawUserValues
              .get()
              // Values whose round trip serialization is not stable violate either some user
              // annotations on the type (e.g. @InRange), or the default mutator limits (e.g.
              // default List size limits) and are therefore not suitable for inclusion in the value
              // pool.
              .filter(value -> isSerializationStable(mutator, value))
              .map(value -> mutator.detach((T) value))
              .collect(Collectors.toList());

      if (userValues.isEmpty()) {
        return mutator;
      }

      double p = valuePoolRegistry.extractFirstProbability(type);
      return new ValuePoolMutator<>(mutator, userValues, p);
    }

    /**
     * Checks if {@code serialize(deserialize(serialize(value))) == serialize(value)}.
     *
     * @param mutator
     * @param value
     * @return true if the serialization is stable
     * @param <T>
     */
    @SuppressWarnings("unchecked")
    private static <T> boolean isSerializationStable(SerializingMutator<T> mutator, Object value) {
      ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
      try {
        mutator.write((T) value, new DataOutputStream(byteStream));
        byte[] originalSerialized = byteStream.toByteArray();
        byteStream.reset();

        T roundTrip =
            mutator.read(new DataInputStream(new ByteArrayInputStream(originalSerialized)));
        mutator.write(roundTrip, new DataOutputStream(byteStream));
        byte[] roundTripSerialized = byteStream.toByteArray();
        return Arrays.equals(originalSerialized, roundTripSerialized);
      } catch (Exception e) {
        return false;
      }
    }

    @Override
    public String toDebugString(Predicate<Debuggable> isInCycle) {
      return String.format(
          "%s (values: %d p: %.2f)",
          mutator.toDebugString(isInCycle), userValues.size(), poolUsageProbability);
    }

    @Override
    public T read(DataInputStream in) throws IOException {
      return mutator.read(in);
    }

    @Override
    public void write(T value, DataOutputStream out) throws IOException {
      mutator.write(value, out);
    }

    @Override
    public T detach(T value) {
      return mutator.detach(value);
    }

    @Override
    protected boolean computeHasFixedSize() {
      return mutator.hasFixedSize();
    }

    @Override
    public T init(PseudoRandom prng) {
      if (prng.closedRange(0.0, 1.0) < poolUsageProbability) {
        return prng.pickIn(userValues);
      } else {
        return mutator.init(prng);
      }
    }

    @Override
    public T mutate(T value, PseudoRandom prng) {
      if (prng.closedRange(0.0, 1.0) < poolUsageProbability) {
        if (prng.choice()) {
          return prng.pickIn(userValues);
        } else {
          // treat the value from valuePool as a starting point for mutation
          return mutator.mutate(prng.pickIn(userValues), prng);
        }
      }
      return mutator.mutate(value, prng);
    }

    @Override
    public T crossOver(T value, T otherValue, PseudoRandom prng) {
      return mutator.crossOver(value, otherValue, prng);
    }
  }
}
