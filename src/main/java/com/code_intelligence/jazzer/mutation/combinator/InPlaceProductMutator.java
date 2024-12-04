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

package com.code_intelligence.jazzer.mutation.combinator;

import static com.code_intelligence.jazzer.mutation.support.InputStreamSupport.extendWithZeros;
import static com.code_intelligence.jazzer.mutation.support.Preconditions.requireNonNullElements;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.joining;

import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingInPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.api.ValueMutator;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.function.Predicate;

@SuppressWarnings({"unchecked", "rawtypes"})
public final class InPlaceProductMutator extends SerializingInPlaceMutator<Object[]> {
  // Inverse frequency in which product type mutators should be used in cross over.
  private static final int INVERSE_PICK_VALUE_SUPPLIER_FREQUENCY = 100;

  private final SerializingMutator[] mutators;

  InPlaceProductMutator(SerializingMutator[] mutators) {
    requireNonNullElements(mutators);
    this.mutators = Arrays.copyOf(mutators, mutators.length);
  }

  @Override
  public Object[] read(DataInputStream in) throws IOException {
    Object[] value = new Object[mutators.length];
    for (int i = 0; i < mutators.length; i++) {
      value[i] = mutators[i].read(in);
    }
    return value;
  }

  @Override
  public Object[] readExclusive(InputStream in) throws IOException {
    Object[] value = new Object[mutators.length];
    // mutators can be an empty array. This can so far only happen when an empty Java Bean mutator
    // is used.
    // Returning an empty array and not reading anything from `in` is fine in this case, since the
    // bean cannot be mutated anyway.
    if (mutators.length == 0) {
      return value;
    }
    int lastIndex = mutators.length - 1;
    DataInputStream endlessData = new DataInputStream(extendWithZeros(in));
    for (int i = 0; i < lastIndex; i++) {
      value[i] = mutators[i].read(endlessData);
    }
    value[lastIndex] = mutators[lastIndex].readExclusive(in);
    return value;
  }

  @Override
  public void write(Object[] value, DataOutputStream out) throws IOException {
    for (int i = 0; i < mutators.length; i++) {
      mutators[i].write(value[i], out);
    }
  }

  @Override
  public void writeExclusive(Object[] value, OutputStream out) throws IOException {
    DataOutputStream dataOut = new DataOutputStream(out);
    int lastIndex = mutators.length - 1;
    for (int i = 0; i < lastIndex; i++) {
      mutators[i].write(value[i], dataOut);
    }
    mutators[lastIndex].writeExclusive(value[lastIndex], out);
  }

  @Override
  protected Object[] makeDefaultInstance() {
    return new Object[mutators.length];
  }

  @Override
  public void initInPlace(Object[] reference, PseudoRandom prng) {
    for (int i = 0; i < mutators.length; i++) {
      reference[i] = mutators[i].init(prng);
    }
  }

  @Override
  public void mutateInPlace(Object[] reference, PseudoRandom prng) {
    if (mutators.length == 0) {
      return;
    }
    int i = prng.indexIn(mutators);
    reference[i] = mutators[i].mutate(reference[i], prng);
  }

  @Override
  public void crossOverInPlace(Object[] reference, Object[] otherReference, PseudoRandom prng) {
    for (int i = 0; i < mutators.length; i++) {
      SerializingMutator mutator = mutators[i];
      Object value = reference[i];
      Object otherValue = otherReference[i];
      Object crossedOver =
          prng.pickValue(
              value,
              otherValue,
              () -> mutator.crossOver(value, otherValue, prng),
              INVERSE_PICK_VALUE_SUPPLIER_FREQUENCY);
      if (crossedOver == otherReference) {
        // If otherReference was picked, it needs to be detached as mutating
        // it is prohibited in cross over.
        crossedOver = mutator.detach(crossedOver);
      }
      reference[i] = crossedOver;
    }
  }

  @Override
  protected boolean computeHasFixedSize() {
    return stream(mutators).allMatch(ValueMutator::hasFixedSize);
  }

  @Override
  public Object[] detach(Object[] value) {
    Object[] clone = new Object[mutators.length];
    for (int i = 0; i < mutators.length; i++) {
      clone[i] = mutators[i].detach(value[i]);
    }
    return clone;
  }

  @Override
  public String toDebugString(Predicate<Debuggable> isInCycle) {
    if (isInCycle.test(this)) {
      return "(cycle)";
    }
    return stream(mutators)
        .map(mutator -> mutator.toDebugString(isInCycle))
        .collect(joining(", ", "[", "]"));
  }
}
