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

package com.code_intelligence.jazzer.mutation.mutator.lang;

import static com.code_intelligence.jazzer.mutation.mutator.lang.StringMutatorFactory.fixUpAscii;
import static com.code_intelligence.jazzer.mutation.mutator.lang.StringMutatorFactory.fixUpUtf8;
import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.support.RandomSupport;
import com.google.protobuf.ByteString;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.SplittableRandom;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;

class StringMutatorTest {
  @RepeatedTest(10)
  void testFixAscii_randomInputFixed(RepetitionInfo info) {
    SplittableRandom random = new SplittableRandom(
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
    SplittableRandom random = new SplittableRandom(
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
    SplittableRandom random = new SplittableRandom(
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
    SplittableRandom random = new SplittableRandom(
        (long) "testFixUtf8_validInputNotChanged".hashCode() * info.getCurrentRepetition());

    for (int codePoints = 0; codePoints < 1000; codePoints++) {
      byte[] validUtf8 = generateValidUtf8Bytes(random, codePoints);
      byte[] copy = Arrays.copyOf(validUtf8, validUtf8.length);
      fixUpUtf8(copy);
      assertThat(copy).isEqualTo(validUtf8);
    }
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

  private static byte[] generateRandomBytes(SplittableRandom random, int length) {
    byte[] bytes = new byte[length];
    RandomSupport.nextBytes(random, bytes);
    return bytes;
  }

  private static byte[] generateValidAsciiBytes(SplittableRandom random, int length) {
    return random.ints(0, 0x7F)
        .limit(length)
        .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
        .toString()
        .getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] generateValidUtf8Bytes(SplittableRandom random, long codePoints) {
    return random.ints(0, Character.MAX_CODE_POINT + 1)
        .filter(code -> code < Character.MIN_SURROGATE || code > Character.MAX_SURROGATE)
        .limit(codePoints)
        .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
        .toString()
        .getBytes(StandardCharsets.UTF_8);
  }
}
