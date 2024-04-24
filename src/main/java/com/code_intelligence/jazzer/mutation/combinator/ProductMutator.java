/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
