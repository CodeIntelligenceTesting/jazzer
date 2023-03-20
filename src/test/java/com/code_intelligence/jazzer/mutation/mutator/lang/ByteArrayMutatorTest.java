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
package com.code_intelligence.jazzer.mutation.mutator.lang;

import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.WithLength;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.mutator.libfuzzer.LibFuzzerMutator;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ByteArrayMutatorTest {
  /**
   * Some tests may set {@link LibFuzzerMutator#MOCK_SIZE_KEY} which can interfere with other tests
   * unless cleared.
   */
  @AfterEach
  void cleanMockSize() {
    System.clearProperty(LibFuzzerMutator.MOCK_SIZE_KEY);
  }

  @Test
  void testBasicFunction() {
    SerializingMutator<byte[]> mutator =
        (SerializingMutator<byte[]>) LangMutators.newFactory().createOrThrow(
            new TypeHolder<byte[]>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("Nullable<byte[]>");

    byte[] arr;
    try (MockPseudoRandom prng = mockPseudoRandom(false, 5, new byte[] {1, 2, 3, 4, 5})) {
      arr = mutator.init(prng);
    }
    assertThat(arr).isEqualTo(new byte[] {1, 2, 3, 4, 5});

    try (MockPseudoRandom prng = mockPseudoRandom(false)) {
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

    try (MockPseudoRandom prng = mockPseudoRandom(10)) {
      // init will call closedrange(min, max) and the mock prng will assert that the given value
      // above is between those values which we want to fail here to show that we're properly
      // clamping the range
      Assertions.assertThrows(AssertionError.class, () -> { byte[] arr = mutator.init(prng); });
    }
  }

  @Test
  void testMinLengthInitClamp() {
    SerializingMutator<byte[]> mutator =
        (SerializingMutator<byte[]>) LangMutators.newFactory().createOrThrow(
            new TypeHolder<byte @NotNull @WithLength(min = 5)[]>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("byte[]");

    try (MockPseudoRandom prng = mockPseudoRandom(3)) {
      // init will call closedrange(min, max) and the mock prng will assert that the given value
      // above is between those values which we want to fail here to show that we're properly
      // clamping the range
      Assertions.assertThrows(AssertionError.class, () -> { byte[] arr = mutator.init(prng); });
    }
  }

  @Test
  void testMinLength() {
    SerializingMutator<byte[]> mutator =
        (SerializingMutator<byte[]>) LangMutators.newFactory().createOrThrow(
            new TypeHolder<byte @NotNull @WithLength(min = 5)[]>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("byte[]");

    byte[] arr;
    try (MockPseudoRandom prng = mockPseudoRandom(10, new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10})) {
      arr = mutator.init(prng);
    }
    assertThat(arr).hasLength(10);

    System.setProperty(LibFuzzerMutator.MOCK_SIZE_KEY, "3");

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      arr = mutator.mutate(arr, prng);
    }
    assertThat(arr).hasLength(5);
    assertThat(arr).isEqualTo(new byte[] {2, 4, 6, 0, 0});
  }
}
