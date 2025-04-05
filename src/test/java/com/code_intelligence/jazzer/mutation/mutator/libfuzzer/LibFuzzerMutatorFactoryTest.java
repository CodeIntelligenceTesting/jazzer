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
import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.WithLength;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

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

  static final int DEL_CHUNK = 0;
  static final int INS_BYTE = 1;
  static final int INS_REP = 2;
  static final int MUT_BYTE = 3;
  static final int MUT_BIT = 4;

  static Stream<Arguments> deleteChunk() {
    final byte[] even = new byte[] {0, 1, 2, 3};
    final byte[] odd = new byte[] {0, 1, 2, 3, 4};
    return Stream.of(
        // Even length, delete one byte
        arguments(arguments(DEL_CHUNK, 0, 0), even, new byte[] {1, 2, 3}),
        arguments(arguments(DEL_CHUNK, 0, 0), new byte[] {0, 10, 20, 30}, new byte[] {10, 20, 30}),
        arguments(arguments(DEL_CHUNK, 0, 1), even, new byte[] {0, 2, 3}),
        arguments(arguments(DEL_CHUNK, 0, 2), even, new byte[] {0, 1, 3}),
        arguments(arguments(DEL_CHUNK, 0, 3), even, new byte[] {0, 1, 2}),
        // Delete two bytes
        arguments(arguments(DEL_CHUNK, 1, 0), even, new byte[] {2, 3}),
        arguments(arguments(DEL_CHUNK, 1, 1), even, new byte[] {0, 3}),
        arguments(arguments(DEL_CHUNK, 1, 2), even, new byte[] {0, 1}),
        // Odd length, delete one byte
        arguments(arguments(DEL_CHUNK, 0, 0), odd, new byte[] {1, 2, 3, 4}),
        arguments(arguments(DEL_CHUNK, 0, 1), odd, new byte[] {0, 2, 3, 4}),
        arguments(arguments(DEL_CHUNK, 0, 2), odd, new byte[] {0, 1, 3, 4}),
        arguments(arguments(DEL_CHUNK, 0, 3), odd, new byte[] {0, 1, 2, 4}),
        arguments(arguments(DEL_CHUNK, 0, 4), odd, new byte[] {0, 1, 2, 3}),
        // Delete two bytes
        arguments(arguments(DEL_CHUNK, 1, 0), odd, new byte[] {2, 3, 4}),
        arguments(arguments(DEL_CHUNK, 1, 1), odd, new byte[] {0, 3, 4}),
        arguments(arguments(DEL_CHUNK, 1, 2), odd, new byte[] {0, 1, 4}),
        arguments(arguments(DEL_CHUNK, 1, 3), odd, new byte[] {0, 1, 2}));
  }

  static Stream<Arguments> insertByte() {
    final byte[] input1 = new byte[] {0};
    final byte[] input2 = new byte[] {0, 1};
    final byte[] input3 = new byte[] {0, 1, 2};
    return Stream.of(
        arguments(arguments(INS_BYTE, 0, 10), input1, new byte[] {10, 0}),
        arguments(arguments(INS_BYTE, 1, 20), input1, new byte[] {0, 20}),
        arguments(arguments(INS_BYTE, 0, 10), input2, new byte[] {10, 0, 1}),
        arguments(arguments(INS_BYTE, 1, 20), input2, new byte[] {0, 20, 1}),
        arguments(arguments(INS_BYTE, 2, 30), input2, new byte[] {0, 1, 30}),
        arguments(arguments(INS_BYTE, 0, 10), input3, new byte[] {10, 0, 1, 2}),
        arguments(arguments(INS_BYTE, 1, 20), input3, new byte[] {0, 20, 1, 2}),
        arguments(arguments(INS_BYTE, 2, 30), input3, new byte[] {0, 1, 30, 2}),
        arguments(arguments(INS_BYTE, 3, 40), input3, new byte[] {0, 1, 2, 40}));
  }

  static Stream<Arguments> insertRepeatedBytes() {
    final byte[] input1 = new byte[] {0};
    final byte[] input2 = new byte[] {0, 1};
    return Stream.of(
        arguments(arguments(INS_REP, 0, 1, 10), input1, new byte[] {10, 0}),
        arguments(arguments(INS_REP, 1, 1, 20), input1, new byte[] {0, 20}),
        arguments(arguments(INS_REP, 0, 2, 10), input1, new byte[] {10, 10, 0}),
        arguments(arguments(INS_REP, 1, 2, 20), input1, new byte[] {0, 20, 20}),
        arguments(arguments(INS_REP, 0, 3, 10), input1, new byte[] {10, 10, 10, 0}),
        arguments(arguments(INS_REP, 1, 3, 20), input1, new byte[] {0, 20, 20, 20}),
        arguments(arguments(INS_REP, 0, 1, 10), input2, new byte[] {10, 0, 1}),
        arguments(arguments(INS_REP, 1, 1, 20), input2, new byte[] {0, 20, 1}),
        arguments(arguments(INS_REP, 2, 1, 30), input2, new byte[] {0, 1, 30}),
        arguments(arguments(INS_REP, 0, 2, 10), input2, new byte[] {10, 10, 0, 1}),
        arguments(arguments(INS_REP, 1, 2, 20), input2, new byte[] {0, 20, 20, 1}),
        arguments(arguments(INS_REP, 2, 2, 30), input2, new byte[] {0, 1, 30, 30}));
  }

  static Stream<Arguments> changeByte() {
    final byte[] input1 = new byte[] {0};
    final byte[] input2 = new byte[] {0, 1};
    final byte[] input3 = new byte[] {1, 2, 3};
    return Stream.of(
        arguments(arguments(MUT_BYTE, 0, 1), input1, new byte[] {1}),
        arguments(arguments(MUT_BYTE, 0, 10), input1, new byte[] {10}),
        arguments(arguments(MUT_BYTE, 0, 1), input2, new byte[] {1, 1}),
        arguments(arguments(MUT_BYTE, 0, 10), input2, new byte[] {10, 1}),
        arguments(arguments(MUT_BYTE, 1, 20), input2, new byte[] {0, 20}),
        arguments(arguments(MUT_BYTE, 1, 0), input2, new byte[] {0, 0}),
        arguments(arguments(MUT_BYTE, 0, 1), input3, new byte[] {1, 2, 3}),
        arguments(arguments(MUT_BYTE, 0, 10), input3, new byte[] {10, 2, 3}),
        arguments(arguments(MUT_BYTE, 1, 20), input3, new byte[] {1, 20, 3}),
        arguments(arguments(MUT_BYTE, 1, 0), input3, new byte[] {1, 0, 3}),
        arguments(arguments(MUT_BYTE, 2, 30), input3, new byte[] {1, 2, 30}),
        arguments(arguments(MUT_BYTE, 2, 0), input3, new byte[] {1, 2, 0}));
  }

  static Stream<Arguments> changeBit() {
    final byte[] zeroes = new byte[] {0};
    final byte[] ones = new byte[] {(byte) 0xFF};
    return Stream.of(
        arguments(arguments(MUT_BIT, 0, 0), zeroes, new byte[] {1}),
        arguments(arguments(MUT_BIT, 0, 1), zeroes, new byte[] {2}),
        arguments(arguments(MUT_BIT, 0, 2), zeroes, new byte[] {4}),
        arguments(arguments(MUT_BIT, 0, 3), zeroes, new byte[] {8}),
        arguments(arguments(MUT_BIT, 0, 4), zeroes, new byte[] {16}),
        arguments(arguments(MUT_BIT, 0, 5), zeroes, new byte[] {32}),
        arguments(arguments(MUT_BIT, 0, 6), zeroes, new byte[] {64}),
        arguments(arguments(MUT_BIT, 0, 7), zeroes, new byte[] {(byte) 128}),
        arguments(arguments(MUT_BIT, 0, 0), ones, new byte[] {(byte) 0b11111110}),
        arguments(arguments(MUT_BIT, 0, 1), ones, new byte[] {(byte) 0b11111101}),
        arguments(arguments(MUT_BIT, 0, 2), ones, new byte[] {(byte) 0b11111011}),
        arguments(arguments(MUT_BIT, 0, 3), ones, new byte[] {(byte) 0b11110111}),
        arguments(arguments(MUT_BIT, 0, 4), ones, new byte[] {(byte) 0b11101111}),
        arguments(arguments(MUT_BIT, 0, 5), ones, new byte[] {(byte) 0b11011111}),
        arguments(arguments(MUT_BIT, 0, 6), ones, new byte[] {(byte) 0b10111111}),
        arguments(arguments(MUT_BIT, 0, 7), ones, new byte[] {(byte) 0b01111111}));
  }

  @ParameterizedTest
  @MethodSource({"deleteChunk", "insertByte", "insertRepeatedBytes", "changeByte", "changeBit"})
  void testMutatorOperations(Arguments args, byte[] input, byte[] expected) {
    Optional<SerializingMutator<?>> opt =
        LibFuzzerMutatorFactory.tryCreate(
            new TypeHolder<byte @NotNull @WithLength(max = 5) []>() {}.annotatedType());
    assertThat(opt).isPresent();
    SerializingMutator<byte[]> mutator = (SerializingMutator<byte[]>) opt.get();
    assertThat(mutator.toString()).isEqualTo("byte[]");

    // apply "args" to mockPseudoRandom
    try (MockPseudoRandom prng = mockPseudoRandom(args.get())) {
      assertThat(mutator.mutate(input, prng)).isEqualTo(expected);
    }
  }
}
