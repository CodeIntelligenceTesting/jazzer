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
package com.code_intelligence.jazzer.mutation.mutator.libfuzzer;

import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.WithLength;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import java.util.Optional;
import org.junit.jupiter.api.Test;

@SuppressWarnings("unchecked")
class LibFuzzerMutatorFactoryTest {

  @Test
  void testInit() {
    Optional<SerializingMutator<?>> opt =
        LibFuzzerMutatorFactory.tryCreate(
            new TypeHolder<byte @NotNull @WithLength(max = 5) []>() {}.annotatedType());
    assertThat(opt).isPresent();
    SerializingMutator<byte[]> mutator = (SerializingMutator<byte[]>) opt.get();
    assertThat(mutator.toString()).isEqualTo("byte[]");

    try (MockPseudoRandom prng = mockPseudoRandom(4, new byte[] {0, 1, 2, 3})) {
      byte[] a = mutator.init(prng);
      assertThat(a).isEqualTo(new byte[] {0, 1, 2, 3});
    }
  }

  @Test
  void testEraseByteEvenSize() {
    Optional<SerializingMutator<?>> opt =
        LibFuzzerMutatorFactory.tryCreate(
            new TypeHolder<byte @NotNull @WithLength(max = 5) []>() {}.annotatedType());
    assertThat(opt).isPresent();
    SerializingMutator<byte[]> mutator = (SerializingMutator<byte[]>) opt.get();
    assertThat(mutator.toString()).isEqualTo("byte[]");

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // 0: op - erase byte
            // 1: Number of bytes to erase (+1)
            // 2: start index
            // Erase the first byte
            0,
            0,
            0,
            // Erase the first byte
            0,
            0,
            0,
            // Erase the second byte
            0,
            0,
            1,
            // Erase the third byte
            0,
            0,
            2,
            // Erase the fourth byte
            0,
            0,
            3,
            // Erase the first two bytes
            0,
            1,
            0,
            // Erase the second two bytes
            0,
            1,
            1,
            // Erase the last two bytes
            0,
            1,
            2,
            // Erase the first three bytes should fail
            0,
            2)) {

      final byte[] data = new byte[] {0, 1, 2, 3};

      // One byte
      assertThat(mutator.mutate(data, prng)).isEqualTo(new byte[] {1, 2, 3});
      assertThat(mutator.mutate(new byte[] {0, 10, 20, 30}, prng))
          .isEqualTo(new byte[] {10, 20, 30});
      assertThat(mutator.mutate(data, prng)).isEqualTo(new byte[] {0, 2, 3});
      assertThat(mutator.mutate(data, prng)).isEqualTo(new byte[] {0, 1, 3});
      assertThat(mutator.mutate(data, prng)).isEqualTo(new byte[] {0, 1, 2});

      // Two bytes
      assertThat(mutator.mutate(data, prng)).isEqualTo(new byte[] {2, 3});
      assertThat(mutator.mutate(data, prng)).isEqualTo(new byte[] {0, 3});
      assertThat(mutator.mutate(data, prng)).isEqualTo(new byte[] {0, 1});

      assertThrows(AssertionError.class, () -> mutator.mutate(data, prng));
    }
  }

  @Test
  void testEraseByteOddSize() {
    Optional<SerializingMutator<?>> opt =
        LibFuzzerMutatorFactory.tryCreate(
            new TypeHolder<byte @NotNull @WithLength(max = 5) []>() {}.annotatedType());
    assertThat(opt).isPresent();
    SerializingMutator<byte[]> mutator = (SerializingMutator<byte[]>) opt.get();
    assertThat(mutator.toString()).isEqualTo("byte[]");

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // 0: op - erase byte
            // 1: Number of bytes to erase (+1)
            // 2: start index
            // Erase the first byte
            0,
            0,
            0,
            // Erase the first byte
            0,
            0,
            0,
            // Erase the second byte
            0,
            0,
            1,
            // Erase the third byte
            0,
            0,
            2,
            // Erase the fourth byte
            0,
            0,
            3,
            // Erase the first two bytes
            0,
            1,
            0,
            // Erase the second two bytes
            0,
            1,
            1,
            // Erase the butlast two bytes
            0,
            1,
            2,
            // Erase the last two bytes
            0,
            1,
            3,
            // Erase the first three bytes should fail
            0,
            2)) {
      final byte[] data = new byte[] {0, 1, 2, 3, 4};

      // One byte
      assertThat(mutator.mutate(data, prng)).isEqualTo(new byte[] {1, 2, 3, 4});
      assertThat(mutator.mutate(new byte[] {0, 10, 20, 30, 40}, prng))
          .isEqualTo(new byte[] {10, 20, 30, 40});
      assertThat(mutator.mutate(data, prng)).isEqualTo(new byte[] {0, 2, 3, 4});
      assertThat(mutator.mutate(data, prng)).isEqualTo(new byte[] {0, 1, 3, 4});
      assertThat(mutator.mutate(data, prng)).isEqualTo(new byte[] {0, 1, 2, 4});

      // Two bytes
      assertThat(mutator.mutate(data, prng)).isEqualTo(new byte[] {2, 3, 4});
      assertThat(mutator.mutate(data, prng)).isEqualTo(new byte[] {0, 3, 4});
      assertThat(mutator.mutate(data, prng)).isEqualTo(new byte[] {0, 1, 4});
      assertThat(mutator.mutate(data, prng)).isEqualTo(new byte[] {0, 1, 2});

      assertThrows(AssertionError.class, () -> mutator.mutate(data, prng));
    }
  }

  @Test
  void testInsertRandomByte() {
    Optional<SerializingMutator<?>> opt =
        LibFuzzerMutatorFactory.tryCreate(
            new TypeHolder<byte @NotNull @WithLength(max = 5) []>() {}.annotatedType());
    assertThat(opt).isPresent();
    SerializingMutator<byte[]> mutator = (SerializingMutator<byte[]>) opt.get();
    assertThat(mutator.toString()).isEqualTo("byte[]");

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // 0: op - insertRandomByte
            // 1: Index to insert at
            // 2: Byte to insert
            // Insert 2 at index 0
            1,
            0,
            2,
            // Insert 127 at index 1
            1,
            1,
            127,
            // Insert 2 at index 2
            1,
            2,
            2,
            // Insert 2 at index 1
            1,
            1,
            2,
            // Insert 2 at index 0
            1,
            0,
            2,
            // Insert 2 at index 3
            1,
            3,
            30,
            // Insert 2 at index 2
            1,
            2,
            40,
            // Insert 2 at index 1
            1,
            1,
            50,
            // Insert 2 at index 0
            1,
            0,
            60)) {

      final byte[] data1 = new byte[] {0};

      // One byte
      assertThat(mutator.mutate(data1, prng)).isEqualTo(new byte[] {2, 0});
      assertThat(mutator.mutate(data1, prng)).isEqualTo(new byte[] {0, 127});

      // Two bytes
      final byte[] data2 = new byte[] {0, 1};
      assertThat(mutator.mutate(data2, prng)).isEqualTo(new byte[] {0, 1, 2});
      assertThat(mutator.mutate(data2, prng)).isEqualTo(new byte[] {0, 2, 1});
      assertThat(mutator.mutate(data2, prng)).isEqualTo(new byte[] {2, 0, 1});

      // Three bytes
      final byte[] data3 = new byte[] {0, 1, 2};
      assertThat(mutator.mutate(data3, prng)).isEqualTo(new byte[] {0, 1, 2, 30});
      assertThat(mutator.mutate(data3, prng)).isEqualTo(new byte[] {0, 1, 40, 2});
      assertThat(mutator.mutate(data3, prng)).isEqualTo(new byte[] {0, 50, 1, 2});
      assertThat(mutator.mutate(data3, prng)).isEqualTo(new byte[] {60, 0, 1, 2});
    }
  }
}
