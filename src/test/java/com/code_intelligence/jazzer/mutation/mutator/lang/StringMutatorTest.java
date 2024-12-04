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

import static com.code_intelligence.jazzer.mutation.mutator.lang.StringMutatorFactory.fixUpAscii;
import static com.code_intelligence.jazzer.mutation.mutator.lang.StringMutatorFactory.fixUpPchar;
import static com.code_intelligence.jazzer.mutation.mutator.lang.StringMutatorFactory.fixUpUtf8;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.anyPseudoRandom;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.UrlSegment;
import com.code_intelligence.jazzer.mutation.annotation.WithUtf8Length;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.engine.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.mutator.libfuzzer.LibFuzzerMutate;
import com.code_intelligence.jazzer.mutation.support.RandomSupport;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.google.protobuf.ByteString;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.SplittableRandom;
import org.junit.jupiter.api.*;

class StringMutatorTest {
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

  @RepeatedTest(10)
  void testFixAscii_randomInputFixed(RepetitionInfo info) {
    SplittableRandom random =
        new SplittableRandom(
            (long) "testFixAscii_randomInputFixed".hashCode() * info.getCurrentRepetition());

    for (int length = 0; length < 1000; length++) {
      byte[] randomBytes = generateRandomBytes(random, length);
      byte[] copy = Arrays.copyOf(randomBytes, randomBytes.length);
      fixUpAscii(copy);
      if (isValidAscii(randomBytes)) {
        assertThat(copy).isEqualTo(randomBytes);
      } else {
        assertThat(isValidAscii(copy)).isTrue();
      }
    }
  }

  @RepeatedTest(10)
  void testFixAscii_validInputNotChanged(RepetitionInfo info) {
    SplittableRandom random =
        new SplittableRandom(
            (long) "testFixAscii_validInputNotChanged".hashCode() * info.getCurrentRepetition());

    for (int codePoints = 0; codePoints < 1000; codePoints++) {
      byte[] validAscii = generateValidAsciiBytes(random, codePoints);
      byte[] copy = Arrays.copyOf(validAscii, validAscii.length);
      fixUpAscii(copy);
      assertThat(copy).isEqualTo(validAscii);
    }
  }

  @RepeatedTest(20)
  void testFixUtf8_randomInputFixed(RepetitionInfo info) {
    SplittableRandom random =
        new SplittableRandom(
            (long) "testFixUtf8_randomInputFixed".hashCode() * info.getCurrentRepetition());

    for (int length = 0; length < 1000; length++) {
      byte[] randomBytes = generateRandomBytes(random, length);
      byte[] copy = Arrays.copyOf(randomBytes, randomBytes.length);
      fixUpUtf8(copy);
      if (isValidUtf8(randomBytes)) {
        assertThat(copy).isEqualTo(randomBytes);
      } else {
        assertThat(isValidUtf8(copy)).isTrue();
      }
    }
  }

  @RepeatedTest(20)
  void testFixUtf8_validInputNotChanged(RepetitionInfo info) {
    SplittableRandom random =
        new SplittableRandom(
            (long) "testFixUtf8_validInputNotChanged".hashCode() * info.getCurrentRepetition());

    for (int codePoints = 0; codePoints < 1000; codePoints++) {
      byte[] validUtf8 = generateValidUtf8Bytes(random, codePoints);
      byte[] copy = Arrays.copyOf(validUtf8, validUtf8.length);
      fixUpUtf8(copy);
      assertThat(copy).isEqualTo(validUtf8);
    }
  }

  @RepeatedTest(10)
  void testFixPchar_randomInputFixed(RepetitionInfo info) {
    SplittableRandom random =
        new SplittableRandom(
            (long) "testFixPchar_randomInputFixed".hashCode() * info.getCurrentRepetition());

    for (int length = 0; length < 1000; length++) {
      byte[] randomBytes = generateRandomBytes(random, length);
      byte[] copy = Arrays.copyOf(randomBytes, randomBytes.length);
      fixUpPchar(copy);
      if (isValidPathVariable(randomBytes)) {
        assertThat(copy).isEqualTo(randomBytes);
      } else {
        assertThat(isValidAscii(copy)).isTrue();
      }
    }
  }

  @Test
  void testUrlSegmentInit() {
    SerializingMutator<String> mutator =
        (SerializingMutator<String>)
            factory.createOrThrow(
                new TypeHolder<
                    @NotNull @UrlSegment @WithUtf8Length(min = 10) String>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("String");
    PseudoRandom prng = anyPseudoRandom();
    for (int i = 0; i < 1000; i++) {
      String urlSegment = mutator.init(prng);
      assertThat(urlSegment.length()).isAtLeast(10);
      assertThat(isValidPathVariable(urlSegment.getBytes(StandardCharsets.UTF_8))).isTrue();
    }
  }

  @Test
  void testMinLengthInit() {
    SerializingMutator<String> mutator =
        (SerializingMutator<String>)
            factory.createOrThrow(
                new TypeHolder<@NotNull @WithUtf8Length(min = 10) String>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("String");

    try (MockPseudoRandom prng = mockPseudoRandom(5)) {
      // mock prng should throw an assert error when given a lower value than min
      Assertions.assertThrows(
          AssertionError.class,
          () -> {
            String s = mutator.init(prng);
          });
    }
  }

  @Test
  void testMaxLengthInit() {
    SerializingMutator<String> mutator =
        (SerializingMutator<String>)
            factory.createOrThrow(
                new TypeHolder<@NotNull @WithUtf8Length(max = 50) String>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("String");

    try (MockPseudoRandom prng = mockPseudoRandom(60)) {
      // mock prng should throw an assert error when given a value higher than max
      Assertions.assertThrows(
          AssertionError.class,
          () -> {
            String s = mutator.init(prng);
          });
    }
  }

  @Test
  void testMinLengthMutate() {
    SerializingMutator<String> mutator =
        (SerializingMutator<String>)
            factory.createOrThrow(
                new TypeHolder<@NotNull @WithUtf8Length(min = 10) String>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("String");

    String s;
    try (MockPseudoRandom prng = mockPseudoRandom(10, "foobarbazf".getBytes())) {
      s = mutator.init(prng);
    }
    assertThat(s).isEqualTo("foobarbazf");

    System.setProperty(LibFuzzerMutate.MOCK_SIZE_KEY, "5");
    try (MockPseudoRandom prng = mockPseudoRandom()) {
      s = mutator.mutate(s, prng);
    }
    assertThat(s).isEqualTo("gqrff\0\0\0\0\0");
  }

  @Test
  void testMaxLengthMutate() {
    SerializingMutator<String> mutator =
        (SerializingMutator<String>)
            factory.createOrThrow(
                new TypeHolder<@NotNull @WithUtf8Length(max = 15) String>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("String");

    String s;
    try (MockPseudoRandom prng = mockPseudoRandom(10, "foobarbazf".getBytes())) {
      s = mutator.init(prng);
    }
    assertThat(s).isEqualTo("foobarbazf");

    System.setProperty(LibFuzzerMutate.MOCK_SIZE_KEY, "20");
    try (MockPseudoRandom prng = mockPseudoRandom()) {
      Assertions.assertThrows(
          ArrayIndexOutOfBoundsException.class,
          () -> {
            String s2 = mutator.mutate(s, prng);
          });
    }
  }

  @Test
  void testMultibyteCharacters() {
    SerializingMutator<String> mutator =
        (SerializingMutator<String>)
            factory.createOrThrow(
                new TypeHolder<@NotNull @WithUtf8Length(min = 10) String>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("String");

    String s;
    try (MockPseudoRandom prng =
        mockPseudoRandom(10, "foobarÖÖ".getBytes(StandardCharsets.UTF_8))) {
      s = mutator.init(prng);
    }
    assertThat(s).hasLength(8);
    assertThat(s).isEqualTo("foobarÖÖ");
  }

  private static boolean isValidUtf8(byte[] data) {
    return ByteString.copyFrom(data).isValidUtf8();
  }

  private static boolean isValidAscii(byte[] data) {
    for (byte b : data) {
      if ((b & 0xFF) > 0x7F) {
        return false;
      }
    }
    return true;
  }

  private static final byte[] VALID_PCHAR =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:@!$&'()*+,;=".getBytes();

  private static boolean isValidPathVariable(byte[] data) {
    for (byte b : data) {
      if (!isValidPathChar(b)) {
        return false;
      }
    }
    return true;
  }

  private static boolean isValidPathChar(byte b) {
    for (byte valid : VALID_PCHAR) {
      if (b == valid) {
        return true;
      }
    }
    return false;
  }

  private static byte[] generateRandomBytes(SplittableRandom random, int length) {
    byte[] bytes = new byte[length];
    RandomSupport.nextBytes(random, bytes);
    return bytes;
  }

  private static byte[] generateValidAsciiBytes(SplittableRandom random, int length) {
    return random
        .ints(0, 0x7F)
        .limit(length)
        .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
        .toString()
        .getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] generateValidUtf8Bytes(SplittableRandom random, long codePoints) {
    return random
        .ints(0, Character.MAX_CODE_POINT + 1)
        .filter(code -> code < Character.MIN_SURROGATE || code > Character.MAX_SURROGATE)
        .limit(codePoints)
        .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
        .toString()
        .getBytes(StandardCharsets.UTF_8);
  }
}
