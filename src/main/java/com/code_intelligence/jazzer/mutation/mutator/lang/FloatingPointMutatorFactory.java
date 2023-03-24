/*
 * Copyright 2023 Code Intelligence GmbH
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

import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static java.lang.String.format;

import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.mutator.libfuzzer.LibFuzzerMutator;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.AnnotatedType;
import java.util.Optional;
import java.util.function.Predicate;

final class FloatingPointMutatorFactory extends MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(AnnotatedType type, MutatorFactory factory) {
    if (!(type.getType() instanceof Class)) {
      return Optional.empty();
    }
    Class<?> clazz = (Class<?>) type.getType();

    if (clazz == float.class || clazz == Float.class) {
      return Optional.of(new FloatMutator(type, -Float.MAX_VALUE, Float.MAX_VALUE));
    } else if (clazz == double.class || clazz == Double.class) {
      return Optional.of(new DoubleMutator(type, -Double.MAX_VALUE, Double.MAX_VALUE));
    } else {
      return Optional.empty();
    }
  }

  private static final class FloatMutator extends SerializingMutator<Float> {
    FloatMutator(AnnotatedType type, Float defaultMinValueForType, Float defaultMaxValueForType) {}

    public Float mutateWithLibFuzzer(Float value) {
      return LibFuzzerMutator.mutateKnownValues(value, this, 0);
    }

    // TODO: randomly init to special values like NaN, -0, +0, +Inf, -Inf
    @Override
    public Float init(PseudoRandom prng) {
      return prng.closedRange(-Float.MAX_VALUE, Float.MAX_VALUE);
    }

    // TODO: consider current value when mutating
    @Override
    public Float mutate(Float value, PseudoRandom prng) {
      return prng.closedRange(-Float.MAX_VALUE, Float.MAX_VALUE);
    }

    @Override
    public Float crossOver(Float value, Float otherValue, PseudoRandom prng) {
      return prng.closedRange(-Float.MAX_VALUE, Float.MAX_VALUE);
    }

    @Override
    public Float read(DataInputStream in) throws IOException {
      return in.readFloat();
    }

    @Override
    public void write(Float value, DataOutputStream out) throws IOException {
      out.writeFloat(value);
    }

    @Override
    public Float detach(Float value) {
      return value;
    }

    @Override
    public String toDebugString(Predicate<Debuggable> isInCycle) {
      return "Float";
    }
  }

  private static final class DoubleMutator extends SerializingMutator<Double> {
    DoubleMutator(
        AnnotatedType type, Double defaultMinValueForType, Double defaultMaxValueForType) {}

    public Double mutateWithLibFuzzer(Double value) {
      return LibFuzzerMutator.mutateKnownValues(value, this, 0);
    }

    // TODO: mix in special values like NaN, -0, +0, +Inf, -Inf
    @Override
    public Double init(PseudoRandom prng) {
      // using "random.nextDouble(-Double.MAX_VALUE, Double.MAX_VALUE);" is not possible.
      // TODO: find out why
      return prng.closedRange(-1e100, 1e100);
    }

    // TODO: consider current value when mutating
    @Override
    public Double mutate(Double value, PseudoRandom prng) {
      // using "random.nextDouble(-Double.MAX_VALUE, Double.MAX_VALUE);" is not possible.
      // TODO: find out why
      return prng.closedRange(-1e100, 1e100);
    }

    @Override
    public Double crossOver(Double value, Double otherValue, PseudoRandom prng) {
      return prng.closedRange(-1e100, 1e100);
    }

    @Override
    public Double read(DataInputStream in) throws IOException {
      return in.readDouble();
    }

    @Override
    public void write(Double value, DataOutputStream out) throws IOException {
      out.writeDouble(value);
    }

    @Override
    public Double detach(Double value) {
      return value;
    }

    @Override
    public String toDebugString(Predicate<Debuggable> isInCycle) {
      return "Double";
    }
  }
}
