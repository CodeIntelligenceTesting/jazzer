package com.code_intelligence.jazzer.mutation.mutator.lang;
/*
 * Copyright 2023 Code Intelligence GmbH
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

import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.WithLength;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import org.junit.jupiter.api.Test;

public class ByteArrayMutatorTest {
  @Test
  void testBasicFunction() {
    SerializingMutator<byte @NotNull[]> mutator =
        (SerializingMutator<byte[]>) LangMutators.newFactory().createOrThrow(
            new TypeHolder<byte @NotNull[]>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("byte[]");

    byte[] arr;
    try (MockPseudoRandom prng = mockPseudoRandom(5, new byte[] {1, 2, 3, 4, 5})) {
      arr = mutator.init(prng);
    }
    assertThat(arr).isEqualTo(new byte[] {1, 2, 3, 4, 5});

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      arr = mutator.mutate(arr, prng);
    }
    assertThat(arr).isEqualTo(new byte[] {2, 4, 6, 8, 10, 6, 7, 8, 9});
  }

  @Test
  void testMaxLength() {
    SerializingMutator<byte[]> mutator =
        (SerializingMutator<byte[]>) LangMutators.newFactory().createOrThrow(
            new TypeHolder<byte @NotNull @WithLength(max = 10)[]>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("byte[]");

    byte[] arr;
    try (MockPseudoRandom prng = mockPseudoRandom(8, new byte[] {1, 2, 3, 4, 5, 6, 7, 8})) {
      arr = mutator.init(prng);
    }
    assertThat(arr).isEqualTo(new byte[] {1, 2, 3, 4, 5, 6, 7, 8});

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      arr = mutator.mutate(arr, prng);
    }
    assertThat(arr).hasLength(10);
    assertThat(arr).isEqualTo(new byte[] {2, 4, 6, 8, 10, 12, 14, 16, 9, 10});

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      arr = mutator.mutate(arr, prng);
    }
    assertThat(arr).hasLength(10);
    assertThat(arr).isEqualTo(new byte[] {3, 6, 9, 12, 15, 18, 21, 24, 18, 20});
  }

  @Test
  void testMaxLengthInitClamp() {
    SerializingMutator<byte[]> mutator =
        (SerializingMutator<byte[]>) LangMutators.newFactory().createOrThrow(
            new TypeHolder<byte @NotNull @WithLength(max = 5)[]>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("byte[]");

    byte[] arr;
    try (MockPseudoRandom prng = mockPseudoRandom(10, new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10})) {
      arr = mutator.init(prng);
    } catch (AssertionError e) {
      assertThat(e).isNotNull();
    }
  }

  @Test
  void testMinLengthInitClamp() {
    SerializingMutator<byte[]> mutator =
        (SerializingMutator<byte[]>) LangMutators.newFactory().createOrThrow(
            new TypeHolder<byte @NotNull @WithLength(min = 5)[]>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("byte[]");

    // The mock libfuzzer mutator doesn't currently support outputting less data than it's given, so
    // it's impossible to init an array with enough elements and then mutate it into one that has
    // too few elements.

    // This only tests that init will properly clamp to the minimum length by checking that the mock
    // prng has a failed assertion that it's asking for 5 elements in the init array rather than the
    // 3 we've provided
    byte[] arr;
    try (MockPseudoRandom prng = mockPseudoRandom(3, new byte[] {1, 2, 3})) {
      arr = mutator.init(prng);
    } catch (AssertionError e) {
      assertThat(e).isNotNull();
    }
  }
}
