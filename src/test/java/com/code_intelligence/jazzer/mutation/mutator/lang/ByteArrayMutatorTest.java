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

import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.WithLength;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.engine.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.mutator.libfuzzer.LibFuzzerMutate;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@SuppressWarnings({"unchecked"})
public class ByteArrayMutatorTest {
  ChainedMutatorFactory factory;

  @BeforeEach
  void createFactory() {
    factory = ChainedMutatorFactory.of(LangMutators.newFactories());
  }

  /**
   * Some tests may set {@link LibFuzzerMutate#MOCK_SIZE_KEY} which can interfere with other tests
   * unless cleared.
   */
  @AfterEach
  void cleanMockSize() {
    System.clearProperty(LibFuzzerMutate.MOCK_SIZE_KEY);
  }

  @Test
  void testBasicFunction() {
    SerializingMutator<byte[]> mutator =
        (SerializingMutator<byte[]>)
            factory.createOrThrow(new TypeHolder<byte[]>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("Nullable<byte[]>");

    byte[] arr;
    try (MockPseudoRandom prng = mockPseudoRandom(false, 5, new byte[] {1, 2, 3, 4, 5})) {
      arr = mutator.init(prng);
    }
    assertThat(arr).isEqualTo(new byte[] {1, 2, 3, 4, 5});

    System.setProperty(LibFuzzerMutate.MOCK_SIZE_KEY, "10");
    try (MockPseudoRandom prng = mockPseudoRandom(false)) {
      arr = mutator.mutate(arr, prng);
    }
    assertThat(arr).isEqualTo(new byte[] {2, 4, 6, 8, 10, 6, 7, 8, 9, 10});
  }

  @Test
  void testMaxLength() {
    SerializingMutator<byte[]> mutator =
        (SerializingMutator<byte[]>)
            factory.createOrThrow(
                new TypeHolder<byte @NotNull @WithLength(max = 10) []>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("byte[]");

    byte[] arr;
    try (MockPseudoRandom prng = mockPseudoRandom(8, new byte[] {1, 2, 3, 4, 5, 6, 7, 8})) {
      arr = mutator.init(prng);
    }
    assertThat(arr).isEqualTo(new byte[] {1, 2, 3, 4, 5, 6, 7, 8});

    System.setProperty(LibFuzzerMutate.MOCK_SIZE_KEY, "11");
    try (MockPseudoRandom prng = mockPseudoRandom()) {
      // the ByteArrayMutator will limit the maximum size of the data requested from libfuzzer to
      // WithLength::max so setting the mock mutator to make it bigger will cause an exception
      assertThrows(
          ArrayIndexOutOfBoundsException.class,
          () -> {
            mutator.mutate(arr, prng);
          });
    }
  }

  @Test
  void testMaxLengthInitClamp() {
    SerializingMutator<byte[]> mutator =
        (SerializingMutator<byte[]>)
            factory.createOrThrow(
                new TypeHolder<byte @NotNull @WithLength(max = 5) []>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("byte[]");

    try (MockPseudoRandom prng = mockPseudoRandom(10)) {
      // init will call closedRange(min, max) and the mock prng will assert that the given value
      // above is between those values which we want to fail here to show that we're properly
      // clamping the range
      assertThrows(
          AssertionError.class,
          () -> {
            mutator.init(prng);
          });
    }
  }

  @Test
  void testMinLengthInitClamp() {
    SerializingMutator<byte[]> mutator =
        (SerializingMutator<byte[]>)
            factory.createOrThrow(
                new TypeHolder<byte @NotNull @WithLength(min = 5) []>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("byte[]");

    try (MockPseudoRandom prng = mockPseudoRandom(3)) {
      // init will call closedrange(min, max) and the mock prng will assert that the given value
      // above is between those values which we want to fail here to show that we're properly
      // clamping the range
      assertThrows(
          AssertionError.class,
          () -> {
            mutator.init(prng);
          });
    }
  }

  @Test
  void testMinLength() {
    SerializingMutator<byte[]> mutator =
        (SerializingMutator<byte[]>)
            factory.createOrThrow(
                new TypeHolder<byte @NotNull @WithLength(min = 5) []>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("byte[]");

    byte[] arr;
    try (MockPseudoRandom prng = mockPseudoRandom(10, new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10})) {
      arr = mutator.init(prng);
    }
    assertThat(arr).hasLength(10);

    System.setProperty(LibFuzzerMutate.MOCK_SIZE_KEY, "3");

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      arr = mutator.mutate(arr, prng);
    }
    assertThat(arr).hasLength(5);
    assertThat(arr).isEqualTo(new byte[] {2, 4, 6, 0, 0});
  }

  @Test
  void testCrossOver() {
    SerializingMutator<byte[]> mutator =
        (SerializingMutator<byte[]>)
            factory.createOrThrow(new TypeHolder<byte @NotNull []>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("byte[]");

    byte[] value = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    byte[] otherValue = {10, 11, 12, 13, 14, 15, 16, 17, 18, 19};

    byte[] crossedOver;
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // intersect arrays
            0,
            // out length
            8,
            // copy 3 from first
            3,
            // copy 1 from second
            1,
            // copy 1 from first,
            1,
            // copy 3 from second
            3)) {
      crossedOver = mutator.crossOver(value, otherValue, prng);
      assertThat(crossedOver).isEqualTo(new byte[] {0, 1, 2, 10, 3, 11, 12, 13});
    }

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // insert into action
            1,
            // copy size
            3,
            // from position
            5,
            // to position
            2)) {
      crossedOver = mutator.crossOver(value, otherValue, prng);
      assertThat(crossedOver).isEqualTo(new byte[] {0, 1, 15, 16, 17, 2, 3, 4, 5, 6, 7, 8, 9});
    }

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // overwrite action
            2,
            // to position
            3,
            // copy size
            3,
            // from position
            4)) {
      crossedOver = mutator.crossOver(value, otherValue, prng);
      assertThat(crossedOver).isEqualTo(new byte[] {0, 1, 2, 14, 15, 16, 6, 7, 8, 9});
    }
  }
}
