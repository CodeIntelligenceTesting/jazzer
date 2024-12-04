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

import static java.util.Objects.requireNonNull;

import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import net.jodah.typetools.TypeResolver;

abstract class PostComposedMutator<T, R> extends SerializingMutator<R> {
  protected final SerializingMutator<T> mutator;
  private final Function<T, R> map;
  private final Function<R, T> inverse;

  PostComposedMutator(SerializingMutator<T> mutator, Function<T, R> map, Function<R, T> inverse) {
    this(() -> mutator, map, inverse, self -> {});
  }

  PostComposedMutator(
      Supplier<SerializingMutator<T>> mutator,
      Function<T, R> map,
      Function<R, T> inverse,
      Consumer<SerializingMutator<R>> registerSelf) {
    registerSelf.accept(this);
    this.mutator = requireNonNull(mutator).get();
    this.map = requireNonNull(map);
    this.inverse = requireNonNull(inverse);
  }

  @Override
  public R detach(R value) {
    return map.apply(mutator.detach(inverse.apply(value)));
  }

  @Override
  public final R init(PseudoRandom prng) {
    return map.apply(mutator.init(prng));
  }

  @Override
  public final R mutate(R value, PseudoRandom prng) {
    return map.apply(mutator.mutate(inverse.apply(value), prng));
  }

  @Override
  public R crossOver(R value, R otherValue, PseudoRandom prng) {
    return map.apply(mutator.crossOver(inverse.apply(value), inverse.apply(otherValue), prng));
  }

  @Override
  protected boolean computeHasFixedSize() {
    return mutator.hasFixedSize();
  }

  @Override
  public final R read(DataInputStream in) throws IOException {
    return map.apply(mutator.read(in));
  }

  @Override
  public final void write(R value, DataOutputStream out) throws IOException {
    mutator.write(inverse.apply(value), out);
  }

  @Override
  public final R readExclusive(InputStream in) throws IOException {
    return map.apply(mutator.readExclusive(in));
  }

  @Override
  public final void writeExclusive(R value, OutputStream out) throws IOException {
    mutator.writeExclusive(inverse.apply(value), out);
  }

  @Override
  public String toDebugString(Predicate<Debuggable> isInCycle) {
    Class<?> returnType = TypeResolver.resolveRawArguments(Function.class, map.getClass())[1];
    return mutator.toDebugString(isInCycle) + " -> " + returnType.getSimpleName();
  }
}
