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

package com.code_intelligence.jazzer.mutation.support;

import static com.code_intelligence.jazzer.mutation.support.Preconditions.requireNonNullElements;
import static com.google.common.truth.Truth.assertThat;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toCollection;

import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.engine.SeededPseudoRandom;
import com.google.errorprone.annotations.CheckReturnValue;
import com.google.errorprone.annotations.MustBeClosed;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.util.ArrayDeque;
import java.util.Queue;
import java.util.function.Function;

public final class TestSupport {
  private static final DataOutputStream nullDataOutputStream =
      new DataOutputStream(new OutputStream() {
        @Override
        public void write(int i) {}
      });

  private TestSupport() {}

  public static DataOutputStream nullDataOutputStream() {
    return nullDataOutputStream;
  }

  /**
   * Deterministically creates a new instance of {@link PseudoRandom} whose exact behavior is
   * intentionally unspecified.
   */
  // TODO: Turn usages of this function into fuzz tests.
  public static PseudoRandom anyPseudoRandom() {
    // Change this seed from time to time to shake out tests relying on hardcoded behavior.
    return new SeededPseudoRandom(8853461259049838337L);
  }

  /**
   * Creates a {@link PseudoRandom} whose methods return the given values in order.
   */
  @MustBeClosed
  public static MockPseudoRandom mockPseudoRandom(Object... returnValues) {
    return new MockPseudoRandom(returnValues);
  }

  @CheckReturnValue
  public static <T> SerializingMutator<T> mockMutator(T initialValue, Function<T, T> mutate) {
    return new SerializingMutator<T>() {
      @Override
      public T read(DataInputStream in) {
        return initialValue;
      }

      @Override
      public void write(T value, DataOutputStream out) {
        throw new UnsupportedOperationException("mockMutator does not support write");
      }

      @Override
      public T init(PseudoRandom prng) {
        return initialValue;
      }

      @Override
      public T mutate(T value, PseudoRandom prng) {
        return mutate.apply(value);
      }

      @Override
      public String toString() {
        if (initialValue == null) {
          return "null";
        }
        return initialValue.getClass().getSimpleName();
      }

      @Override
      public T detach(T value) {
        return value;
      }
    };
  }

  public static final class MockPseudoRandom implements PseudoRandom, AutoCloseable {
    private final Queue<Object> elements;

    private MockPseudoRandom(Object... objects) {
      requireNonNullElements(objects);
      this.elements = stream(objects).collect(toCollection(ArrayDeque::new));
    }

    @Override
    public boolean nextBoolean() {
      assertThat(elements).isNotEmpty();
      return (boolean) elements.poll();
    }

    @Override
    public int nextInt() {
      assertThat(elements).isNotEmpty();
      return (int) elements.poll();
    }

    @Override
    public int nextInt(int upperExclusive) {
      assertThat(elements).isNotEmpty();
      return (int) elements.poll();
    }

    @Override
    public int nextInt(int lowerInclusive, int upperExclusive) {
      assertThat(elements).isNotEmpty();
      return (int) elements.poll();
    }

    @Override
    public void close() {
      assertThat(elements).isEmpty();
    }
  }
}
