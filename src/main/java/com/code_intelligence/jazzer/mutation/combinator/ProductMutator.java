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

import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.function.Predicate;

@SuppressWarnings("rawtypes")
public final class ProductMutator extends SerializingMutator<Object[]> {

  private final InPlaceProductMutator mutator;
  private final int length;

  ProductMutator(SerializingMutator[] mutators) {
    this.mutator = new InPlaceProductMutator(mutators);
    this.length = mutators.length;
  }

  @Override
  public Object[] read(DataInputStream in) throws IOException {
    return mutator.read(in);
  }

  @Override
  public Object[] readExclusive(InputStream in) throws IOException {
    return mutator.readExclusive(in);
  }

  @Override
  public void write(Object[] value, DataOutputStream out) throws IOException {
    mutator.write(value, out);
  }

  @Override
  public void writeExclusive(Object[] value, OutputStream out) throws IOException {
    mutator.writeExclusive(value, out);
  }

  @Override
  public Object[] init(PseudoRandom prng) {
    Object[] objects = new Object[length];
    mutator.initInPlace(objects, prng);
    return objects;
  }

  @Override
  public Object[] mutate(Object[] value, PseudoRandom prng) {
    Object[] references = detach(value);
    mutator.mutateInPlace(references, prng);
    return references;
  }

  @Override
  public Object[] crossOver(Object[] value, Object[] otherValue, PseudoRandom prng) {
    Object[] references = detach(value);
    // No need to detach otherValue as it is not modified by crossOverInPlace.
    mutator.crossOverInPlace(references, otherValue, prng);
    return references;
  }

  @Override
  protected boolean computeHasFixedSize() {
    return mutator.hasFixedSize();
  }

  @Override
  public Object[] detach(Object[] value) {
    return mutator.detach(value);
  }

  @Override
  public String toDebugString(Predicate<Debuggable> isInCycle) {
    return mutator.toDebugString(isInCycle);
  }
}
