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

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateThenMapToImmutable;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.*;

import com.code_intelligence.jazzer.mutation.annotation.Ascii;
import com.code_intelligence.jazzer.mutation.annotation.UrlSegment;
import com.code_intelligence.jazzer.mutation.annotation.WithUtf8Length;
import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.mutator.libfuzzer.LibFuzzerMutatorFactory;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import java.lang.reflect.AnnotatedType;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.function.Predicate;

final class StringMutatorFactory implements MutatorFactory {
  private static final int HEADER_MASK = 0b1100_0000;
  private static final int BODY_MASK = 0b0011_1111;
  private static final int CONTINUATION_HEADER = 0b1000_0000;

  private static final int DEFAULT_MIN_BYTES = 0;

  private static final int DEFAULT_MAX_BYTES = 1000;

  static void fixUpAscii(byte[] bytes) {
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] &= 0x7F;
    }
  }

  // Based on
  // https://github.com/google/libprotobuf-mutator/blob/af3bb18749db3559dc4968dd85319d05168d4b5e/src/utf8_fix.cc#L32
  // SPDX: Apache-2.0
  // Copyright 2022 Google LLC
  static void fixUpUtf8(byte[] bytes) {
    for (int pos = 0; pos < bytes.length; ) {
      // Leniently read a UTF-8 code point consisting of any byte viewed as the leading byte and up
      // to three following bytes that have a continuation byte header.
      //
      // Since the upper two bits of a byte are 10 with probability 25%, this roughly results in
      // the following distribution for characters:
      //
      // ASCII code point: 75%
      // two-byte UTF-8: 18.75%
      // three-byte UTF-8: ~4.7%
      // four-byte UTF-8: ~1.2%
      int scanPos = pos + 1;
      int maxScanPos = Math.min(pos + 4, bytes.length);

      int codePoint = bytes[pos] & 0xFF;
      for (; scanPos < maxScanPos; scanPos++) {
        byte b = bytes[scanPos];
        if ((b & HEADER_MASK) != CONTINUATION_HEADER) {
          break;
        }
        codePoint = (codePoint << 6) + (b & BODY_MASK);
      }

      int size = scanPos - pos;
      int nextPos = scanPos;
      switch (size) {
        case 1:
          // Force code point to be ASCII.
          codePoint &= 0x7F;

          bytes[pos] = (byte) codePoint;
          break;
        case 2:
          codePoint &= 0x7FF;
          if (codePoint <= 0x7F) {
            // The code point encoding must not be longer than necessary, so fix up the code point
            // to actually require two bytes without fixing too many bits.
            codePoint |= 0x80;
          }

          bytes[--scanPos] = (byte) (CONTINUATION_HEADER | (codePoint & BODY_MASK));
          codePoint >>= 6;
          bytes[pos] = (byte) (0b1100_0000 | codePoint);
          break;
        case 3:
          codePoint &= 0xFFFF;
          if (codePoint <= 0x7FF) {
            // The code point encoding must not be longer than necessary, so fix up the code point
            // to actually require three bytes without fixing too many bits.
            codePoint |= 0x800;
          }
          if (codePoint >= 0xD800 && codePoint <= 0xDFFF) {
            // The code point must not be a low or high UTF-16 surrogate pair, which are not allowed
            // in UTF-8.
            codePoint |= (codePoint & ~0xF000) | 0xE000;
          }

          bytes[--scanPos] = (byte) (CONTINUATION_HEADER | (codePoint & BODY_MASK));
          codePoint >>= 6;
          bytes[--scanPos] = (byte) (CONTINUATION_HEADER | (codePoint & BODY_MASK));
          codePoint >>= 6;
          bytes[pos] = (byte) (0b1110_0000 | codePoint);
          break;
        case 4:
          codePoint &= 0x1FFFFF;
          if (codePoint <= 0xFFFF) {
            // The code point encoding must not be longer than necessary, so fix up the code point
            // to actually require four bytes without fixing too many bits.
            codePoint |= 0x100000;
          }
          if (codePoint > 0x10FFFF) {
            // The code point must be in the valid Unicode range, so fix it up by clearing as few
            // bits as possible.
            codePoint &= ~0x10FFFF;
          }

          bytes[--scanPos] = (byte) (CONTINUATION_HEADER | (codePoint & BODY_MASK));
          codePoint >>= 6;
          bytes[--scanPos] = (byte) (CONTINUATION_HEADER | (codePoint & BODY_MASK));
          codePoint >>= 6;
          bytes[--scanPos] = (byte) (CONTINUATION_HEADER | (codePoint & BODY_MASK));
          codePoint >>= 6;
          bytes[pos] = (byte) (0b1111_0000 | codePoint);
          break;
        default:
          throw new IllegalStateException("Not reached as scanPos <= pos + 4");
      }

      pos = nextPos;
    }
  }

  // Based on pchar definition at https://datatracker.ietf.org/doc/html/rfc3986#appendix-A
  // Don't generate '%' as it needs to be followed by two hex characters.
  //
  // The following array maps all byte values to valid pchars, leaving the initial valid ones
  // untouched.
  // This enables a constant time mapping of individual characters with a uniform distribution.
  // Code to generate the array is located in
  // com.code_intelligence.jazzer.mutation.mutator.lang.PCharGenerator.
  static final byte[] BYTE_TO_PCHAR =
      "!$&'()*+,-.0123456789:;=@ABCDEFGH!IJ$K&'()*+,-.L0123456789:;M=NO@ABCDEFGHIJKLMNOPQRSTUVWXYZPQRS_TabcdefghijklmnopqrstuvwxyzUVW~XYZ_abcdefghijklmnopqrstuvwxyz~!$&'()*+,-.0123456789:;=@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~!$&'()*+,-.01234567"
          .getBytes(StandardCharsets.UTF_8);

  static void fixUpPchar(byte[] bytes) {
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = BYTE_TO_PCHAR[bytes[i] & 0xFF];
    }
  }

  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    return findFirstParentIfClass(type, String.class)
        .flatMap(
            parent -> {
              Optional<WithUtf8Length> utf8Length =
                  Optional.ofNullable(type.getAnnotation(WithUtf8Length.class));
              int min = utf8Length.map(WithUtf8Length::min).orElse(DEFAULT_MIN_BYTES);
              int max = utf8Length.map(WithUtf8Length::max).orElse(DEFAULT_MAX_BYTES);

              AnnotatedType innerByteArray =
                  notNull(withLength(new TypeHolder<byte[]>() {}.annotatedType(), min, max));
              return LibFuzzerMutatorFactory.tryCreate(innerByteArray);
            })
        .map(
            byteArrayMutator -> {
              boolean fixUpAscii = type.getDeclaredAnnotation(Ascii.class) != null;
              boolean fixUpPchar = type.getDeclaredAnnotation(UrlSegment.class) != null;
              return mutateThenMapToImmutable(
                  (SerializingMutator<byte[]>) byteArrayMutator,
                  bytes -> {
                    if (fixUpPchar) {
                      fixUpPchar(bytes);
                    } else if (fixUpAscii) {
                      fixUpAscii(bytes);
                    } else {
                      fixUpUtf8(bytes);
                    }
                    return new String(bytes, StandardCharsets.UTF_8);
                  },
                  string -> string.getBytes(StandardCharsets.UTF_8),
                  (Predicate<Debuggable> inCycle) -> "String");
            });
  }
}
