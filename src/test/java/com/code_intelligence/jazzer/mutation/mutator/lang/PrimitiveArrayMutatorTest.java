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

import static com.code_intelligence.jazzer.mutation.mutator.lang.PrimitiveArrayMutatorFactory.PrimitiveArrayMutator.getBooleanPrimitiveArray;
import static com.code_intelligence.jazzer.mutation.mutator.lang.PrimitiveArrayMutatorFactory.PrimitiveArrayMutator.getBytePrimitiveArray;
import static com.code_intelligence.jazzer.mutation.mutator.lang.PrimitiveArrayMutatorFactory.PrimitiveArrayMutator.getCharPrimitiveArray;
import static com.code_intelligence.jazzer.mutation.mutator.lang.PrimitiveArrayMutatorFactory.PrimitiveArrayMutator.getDoublePrimitiveArray;
import static com.code_intelligence.jazzer.mutation.mutator.lang.PrimitiveArrayMutatorFactory.PrimitiveArrayMutator.getFloatPrimitiveArray;
import static com.code_intelligence.jazzer.mutation.mutator.lang.PrimitiveArrayMutatorFactory.PrimitiveArrayMutator.getIntegerPrimitiveArray;
import static com.code_intelligence.jazzer.mutation.mutator.lang.PrimitiveArrayMutatorFactory.PrimitiveArrayMutator.getLongPrimitiveArray;
import static com.code_intelligence.jazzer.mutation.mutator.lang.PrimitiveArrayMutatorFactory.PrimitiveArrayMutator.getShortPrimitiveArray;
import static com.code_intelligence.jazzer.mutation.mutator.lang.PrimitiveArrayMutatorFactory.PrimitiveArrayMutator.makePrimitiveArrayToBytesConverter;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import java.lang.reflect.AnnotatedArrayType;
import java.lang.reflect.AnnotatedType;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings({"unchecked"})
public class PrimitiveArrayMutatorTest {

  static AnnotatedType annotatedType_int =
      ((AnnotatedArrayType) (new TypeHolder<int[]>() {}.annotatedType()))
          .getAnnotatedGenericComponentType();
  static AnnotatedType annotatedType_long =
      ((AnnotatedArrayType) (new TypeHolder<long[]>() {}.annotatedType()))
          .getAnnotatedGenericComponentType();
  static AnnotatedType annotatedType_short =
      ((AnnotatedArrayType) (new TypeHolder<short[]>() {}.annotatedType()))
          .getAnnotatedGenericComponentType();
  static AnnotatedType annotatedType_byte =
      ((AnnotatedArrayType) (new TypeHolder<byte[]>() {}.annotatedType()))
          .getAnnotatedGenericComponentType();
  static AnnotatedType annotatedType_char =
      ((AnnotatedArrayType) (new TypeHolder<char[]>() {}.annotatedType()))
          .getAnnotatedGenericComponentType();
  static AnnotatedType annotatedType_boolean =
      ((AnnotatedArrayType) (new TypeHolder<boolean[]>() {}.annotatedType()))
          .getAnnotatedGenericComponentType();
  static AnnotatedType annotatedType_float =
      ((AnnotatedArrayType) (new TypeHolder<float[]>() {}.annotatedType()))
          .getAnnotatedGenericComponentType();
  static AnnotatedType annotatedType_double =
      ((AnnotatedArrayType) (new TypeHolder<double[]>() {}.annotatedType()))
          .getAnnotatedGenericComponentType();
  static Function<int[], byte[]> intsToBytes =
      (Function<int[], byte[]>) makePrimitiveArrayToBytesConverter(annotatedType_int);
  static Function<byte[], int[]> bytesToInts =
      getIntegerPrimitiveArray(Integer.MIN_VALUE, Integer.MAX_VALUE);

  static Function<byte[], byte[]> bytesToLibfuzzerBytes =
      (Function<byte[], byte[]>) makePrimitiveArrayToBytesConverter(annotatedType_byte);
  static Function<byte[], byte[]> libfuzzerBytesToBytes =
      getBytePrimitiveArray(Byte.MIN_VALUE, Byte.MAX_VALUE);

  static Function<long[], byte[]> longsToBytes =
      (Function<long[], byte[]>) makePrimitiveArrayToBytesConverter(annotatedType_long);
  static Function<byte[], long[]> bytesToLongs =
      getLongPrimitiveArray(Long.MIN_VALUE, Long.MAX_VALUE);

  static Function<short[], byte[]> shortsToBytes =
      (Function<short[], byte[]>) makePrimitiveArrayToBytesConverter(annotatedType_short);
  static Function<byte[], short[]> bytesToShorts =
      getShortPrimitiveArray(Short.MIN_VALUE, Short.MAX_VALUE);

  static Function<char[], byte[]> charsToBytes =
      (Function<char[], byte[]>) makePrimitiveArrayToBytesConverter(annotatedType_char);
  static Function<byte[], char[]> bytesToChars =
      getCharPrimitiveArray(Character.MIN_VALUE, Character.MAX_VALUE);

  static Function<boolean[], byte[]> booleansToBytes =
      (Function<boolean[], byte[]>) makePrimitiveArrayToBytesConverter(annotatedType_boolean);
  static Function<byte[], boolean[]> bytesToBooleans = getBooleanPrimitiveArray(0, 1);

  static Function<float[], byte[]> floatsToBytes =
      (Function<float[], byte[]>) makePrimitiveArrayToBytesConverter(annotatedType_float);
  static Function<byte[], float[]> bytesToFloats =
      getFloatPrimitiveArray(Float.NEGATIVE_INFINITY, Float.POSITIVE_INFINITY, true);

  static Function<double[], byte[]> doublesToBytes =
      (Function<double[], byte[]>) makePrimitiveArrayToBytesConverter(annotatedType_double);
  static Function<byte[], double[]> bytesToDoubles =
      getDoublePrimitiveArray(Double.NEGATIVE_INFINITY, Double.POSITIVE_INFINITY, true);

  static Stream<Arguments> int2ByteTestCases() {
    return Stream.of(
        arguments(new int[] {0x010203}, new byte[] {0x00, 0x01, 0x02, 0x03}),
        arguments(new int[] {1}, new byte[] {0x00, 0x00, 0x00, 0x1}),
        arguments(new int[] {0x01000000}, new byte[] {0x01, 0x00, 0x00, 0x0}),
        arguments(
            new int[] {1, 2, 3, 4}, new byte[] {0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4}));
  }

  @ParameterizedTest
  @MethodSource("int2ByteTestCases")
  void testArrayConversion_ints2bytes(int[] ints, byte[] bytes) {
    assertThat(intsToBytes.apply(ints)).isEqualTo(bytes);
  }

  static Stream<Arguments> bytes2intsTestCases() {
    return Stream.of(
        arguments(new byte[] {0x01}, new int[] {0x00000001}, Integer.MIN_VALUE, Integer.MAX_VALUE),
        arguments(
            new byte[] {0x01, 0x00}, new int[] {0x00000100}, Integer.MIN_VALUE, Integer.MAX_VALUE),
        arguments(
            new byte[] {0x01, 0x00, 0x00},
            new int[] {0x00010000},
            Integer.MIN_VALUE,
            Integer.MAX_VALUE),
        arguments(
            new byte[] {0x01, 0x00, 0x00, 0x00},
            new int[] {0x01000000},
            Integer.MIN_VALUE,
            Integer.MAX_VALUE),
        arguments(
            new byte[] {(byte) 0xff}, new int[] {0x000000ff}, Integer.MIN_VALUE, Integer.MAX_VALUE),
        arguments(
            new byte[] {(byte) 0xff, (byte) 0x0f},
            new int[] {0x0000ff0f},
            Integer.MIN_VALUE,
            Integer.MAX_VALUE),
        arguments(
            new byte[] {(byte) 0xff}, new int[] {0x000000ff}, Integer.MIN_VALUE, Integer.MAX_VALUE),
        arguments(
            new byte[] {(byte) 0xff, (byte) 0xff},
            new int[] {0x0000ffff},
            Integer.MIN_VALUE,
            Integer.MAX_VALUE),
        arguments(
            new byte[] {(byte) 0xff, 0x00, (byte) 0xff, (byte) 0xff},
            new int[] {0xff00ffff},
            Integer.MIN_VALUE,
            Integer.MAX_VALUE));
  }

  // same for longs
  static Stream<Arguments> bytes2longsTestCases() {
    return Stream.of(
        arguments(new byte[] {0x01}, new long[] {0x00000001}, Long.MIN_VALUE, Long.MAX_VALUE),
        arguments(new byte[] {0x01, 0x00}, new long[] {0x00000100}, Long.MIN_VALUE, Long.MAX_VALUE),
        arguments(
            new byte[] {0x01, 0x00, 0x00}, new long[] {0x00010000}, Long.MIN_VALUE, Long.MAX_VALUE),
        arguments(
            new byte[] {0x01, 0x00, 0x00, 0x00},
            new long[] {0x01000000},
            Long.MIN_VALUE,
            Long.MAX_VALUE),
        arguments(
            new byte[] {0x01, 0x00, 0x00, 0x00, 0x00},
            new long[] {0x0100000000L},
            Long.MIN_VALUE,
            Long.MAX_VALUE),
        arguments(
            new byte[] {0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
            new long[] {0x010000000000L},
            Long.MIN_VALUE,
            Long.MAX_VALUE),
        arguments(
            new byte[] {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            new long[] {0x01000000000000L},
            Long.MIN_VALUE,
            Long.MAX_VALUE),
        arguments(
            new byte[] {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            new long[] {0x0100000000000000L},
            Long.MIN_VALUE,
            Long.MAX_VALUE),
        arguments(
            new byte[] {(byte) 0xff}, new long[] {0x000000ff}, Long.MIN_VALUE, Long.MAX_VALUE),
        arguments(
            new byte[] {(byte) 0xff, (byte) 0x0f},
            new long[] {0x0000ff0f},
            Long.MIN_VALUE,
            Long.MAX_VALUE),
        arguments(
            new byte[] {(byte) 0xff}, new long[] {0x000000ff}, Long.MIN_VALUE, Long.MAX_VALUE),
        arguments(
            new byte[] {(byte) 0xff, (byte) 0xff},
            new long[] {0x0000ffff},
            Long.MIN_VALUE,
            Long.MAX_VALUE),
        arguments(
            new byte[] {(byte) 0xff, 0x00, (byte) 0xff, (byte) 0xff},
            new long[] {0xff00ffffL},
            Long.MIN_VALUE,
            Long.MAX_VALUE),
        arguments(
            new byte[] {(byte) 0xff, 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff},
            new long[] {0xff00ffffffL},
            Long.MIN_VALUE,
            Long.MAX_VALUE),
        arguments(
            new byte[] {(byte) 0xff, 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff},
            new long[] {0xff00ffffffffL},
            Long.MIN_VALUE,
            Long.MAX_VALUE),
        arguments(
            new byte[] {
              (byte) 0xff, 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff
            },
            new long[] {0xff00ffffffffffL},
            Long.MIN_VALUE,
            Long.MAX_VALUE),
        arguments(
            new byte[] {
              (byte) 0xff,
              0x00,
              (byte) 0xff,
              (byte) 0xff,
              (byte) 0xff,
              (byte) 0xff,
              (byte) 0xff,
              (byte) 0xff
            },
            new long[] {0xff00ffffffffffffL},
            Long.MIN_VALUE,
            Long.MAX_VALUE));
  }

  @ParameterizedTest
  @MethodSource("bytes2longsTestCases")
  void testArrayConversion_bytes2longs(byte[] input, long[] expected, long min, long max) {
    Function<byte[], long[]> fn = getLongPrimitiveArray(min, max);
    assertThat(fn.apply(input)).isEqualTo(expected);
  }

  @ParameterizedTest
  @MethodSource("bytes2intsTestCases")
  void testArrayConversion_bytes2ints(byte[] input, int[] expected, int min, int max) {
    Function<byte[], int[]> toInts = getIntegerPrimitiveArray(min, max);
    assertThat(toInts.apply(input)).isEqualTo(expected);
  }

  static Stream<Arguments> bytes2shortsTestCases() {
    return Stream.of(
        arguments(new byte[] {0x01}, new short[] {0x0001}, Short.MIN_VALUE, Short.MAX_VALUE),
        arguments(new byte[] {0x01, 0x00}, new short[] {0x0100}, Short.MIN_VALUE, Short.MAX_VALUE),
        arguments(new byte[] {(byte) 0xff}, new short[] {0x00ff}, Short.MIN_VALUE, Short.MAX_VALUE),
        arguments(
            new byte[] {(byte) 0xff, (byte) 0xff},
            new short[] {(short) 0xffff},
            Short.MIN_VALUE,
            Short.MAX_VALUE),
        arguments(
            new byte[] {(byte) 0xff, 0x00},
            new short[] {(short) 0xff00},
            Short.MIN_VALUE,
            Short.MAX_VALUE));
  }

  @ParameterizedTest
  @MethodSource("bytes2shortsTestCases")
  void testArrayConversion_bytes2shorts(byte[] input, short[] expected, short min, short max) {
    Function<byte[], short[]> fn = getShortPrimitiveArray(min, max);
    assertThat(fn.apply(input)).isEqualTo(expected);
  }

  static Stream<Arguments> bytes2charsTestCases() {
    return Stream.of(
        arguments(new byte[] {0x41}, new char[] {0x41}, Character.MIN_VALUE, Character.MAX_VALUE),
        arguments(
            new byte[] {0x41, 0x41}, new char[] {0x4141}, Character.MIN_VALUE, Character.MAX_VALUE),
        arguments(
            new byte[] {0x01, 0x00},
            new char[] {(char) 0x0100},
            Character.MIN_VALUE,
            Character.MAX_VALUE),
        arguments(
            new byte[] {(byte) 0xff},
            new char[] {(char) 0x00ff},
            Character.MIN_VALUE,
            Character.MAX_VALUE),
        arguments(
            new byte[] {(byte) 0xff, (byte) 0xff},
            new char[] {(char) 0xffff},
            Character.MIN_VALUE,
            Character.MAX_VALUE),
        arguments(
            new byte[] {(byte) 0xff, 0x00},
            new char[] {(char) 0xff00},
            Character.MIN_VALUE,
            Character.MAX_VALUE));
  }

  @ParameterizedTest
  @MethodSource("bytes2charsTestCases")
  void testArrayConversion_bytes2chars(byte[] input, char[] expected, long min, long max) {
    Function<byte[], char[]> fn = getCharPrimitiveArray(min, max);
    assertThat(fn.apply(input)).isEqualTo(expected);
  }

  // same with booleans
  static Stream<Arguments> bytes2booleansTestCases() {
    return Stream.of(
        arguments(new byte[] {0x01}, new boolean[] {true}),
        arguments(
            new byte[] {0, 1, 2, 3, 4, 5, 6},
            new boolean[] {false, true, false, true, false, true, false}),
        arguments(new byte[] {0x00}, new boolean[] {false}),
        arguments(new byte[] {(byte) 0xff}, new boolean[] {true}),
        arguments(new byte[] {(byte) 0x00}, new boolean[] {false}),
        arguments(new byte[] {(byte) 0x01, (byte) 0x00}, new boolean[] {true, false}),
        arguments(new byte[] {(byte) 0x01, (byte) 0x01}, new boolean[] {true, true}),
        arguments(new byte[] {(byte) 0x00, (byte) 0x00}, new boolean[] {false, false}),
        arguments(new byte[] {(byte) 0xff, (byte) 0xff}, new boolean[] {true, true}),
        arguments(new byte[] {(byte) 0xff, (byte) 0x00}, new boolean[] {true, false}),
        arguments(new byte[] {(byte) 0x00, (byte) 0xff}, new boolean[] {false, true}),
        arguments(new byte[] {(byte) 0x00, (byte) 0x01}, new boolean[] {false, true}),
        arguments(
            new byte[] {(byte) 0x01, (byte) 0x00, (byte) 0x01}, new boolean[] {true, false, true}),
        arguments(
            new byte[] {(byte) 0x01, (byte) 0x01, (byte) 0x01}, new boolean[] {true, true, true}),
        arguments(
            new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0x00},
            new boolean[] {false, false, false}),
        arguments(
            new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff}, new boolean[] {true, true, true}),
        arguments(
            new byte[] {(byte) 0xff, (byte) 0x00, (byte) 0xff}, new boolean[] {true, false, true}));
  }

  @ParameterizedTest
  @MethodSource("bytes2booleansTestCases")
  void testArrayConversion_bytes2booleans(byte[] input, boolean[] expected) {
    Function<byte[], boolean[]> fn = getBooleanPrimitiveArray(0, 1);
    assertThat(fn.apply(input)).isEqualTo(expected);
  }

  // same with bytes
  static Stream<Arguments> bytes2bytesTestCases() {
    return Stream.of(
        arguments(new byte[] {1}, new byte[] {0x01}, Byte.MIN_VALUE, Byte.MAX_VALUE),
        arguments(new byte[] {1, 2, 3}, new byte[] {1, 2, 3}, Byte.MIN_VALUE, Byte.MAX_VALUE),
        arguments(
            new byte[] {(byte) 0xff}, new byte[] {(byte) 0xff}, Byte.MIN_VALUE, Byte.MAX_VALUE),
        // reduced domain
        arguments(new byte[] {1, 2, 3}, new byte[] {1, 2, -2}, -2, 2),
        arguments(
            new byte[] {10, 11, 0, -10, -11, -5, 1},
            new byte[] {10, -10, 0, -10, -9, -5, 1},
            -10,
            10));
  }

  @ParameterizedTest
  @MethodSource("bytes2bytesTestCases")
  void testArrayConversion_bytes2bytes(byte[] input, byte[] expected, long min, long max) {
    Function<byte[], byte[]> fn = getBytePrimitiveArray(min, max);
    assertThat(fn.apply(input)).isEqualTo(expected);
  }

  // same with floats
  static Stream<Arguments> bytes2floatsTestCases() {
    return Stream.of(
        arguments(
            new byte[] {(byte) 0xff},
            new float[] {Float.intBitsToFloat(0xff)},
            -Float.MAX_VALUE,
            Float.MAX_VALUE,
            true),
        arguments(
            new byte[] {(byte) 0xff, (byte) 0xff},
            new float[] {Float.intBitsToFloat(0xffff)},
            -Float.MAX_VALUE,
            Float.MAX_VALUE,
            true),
        arguments(
            new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff},
            new float[] {Float.intBitsToFloat(0xffffff)},
            -Float.MAX_VALUE,
            Float.MAX_VALUE,
            true),
        arguments(
            new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff},
            new float[] {Float.intBitsToFloat(0xffffffff)},
            -Float.MAX_VALUE,
            Float.MAX_VALUE,
            true),
        arguments(
            new byte[] {0, 0, 0, 0, 1},
            new float[] {0f, Float.intBitsToFloat(1)},
            -Float.MAX_VALUE,
            Float.MAX_VALUE,
            true),
        arguments(
            new byte[] {0, 0, 0, 0, 1, 1},
            new float[] {0f, Float.intBitsToFloat(0x0101)},
            -Float.MAX_VALUE,
            Float.MAX_VALUE,
            true),
        arguments(
            new byte[] {0, 0, 0, 0, 1, 1, 1},
            new float[] {0f, Float.intBitsToFloat(0x010101)},
            -Float.MAX_VALUE,
            Float.MAX_VALUE,
            true),
        arguments(
            new byte[] {0, 0, 0, 0, 1, 1, 1, 1},
            new float[] {0f, Float.intBitsToFloat(0x01010101)},
            -Float.MAX_VALUE,
            Float.MAX_VALUE,
            true));
  }

  @ParameterizedTest
  @MethodSource("bytes2floatsTestCases")
  void testArrayConversion_bytes2floats(
      byte[] input, float[] expected, float min, float max, boolean allowNan) {
    Function<byte[], float[]> fn = getFloatPrimitiveArray(min, max, allowNan);
    assertThat(fn.apply(input)).isEqualTo(expected);
  }

  // same with doubles
  static Stream<Arguments> bytes2doublesTestCases() {
    return Stream.of(
        arguments(
            new byte[] {(byte) 0xff},
            new double[] {Double.longBitsToDouble(0xff)},
            -Double.MAX_VALUE,
            Double.MAX_VALUE,
            true),
        arguments(
            new byte[] {(byte) 0xff, (byte) 0xff},
            new double[] {Double.longBitsToDouble(0xffff)},
            -Double.MAX_VALUE,
            Double.MAX_VALUE,
            true),
        arguments(
            new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff},
            new double[] {Double.longBitsToDouble(0xffffff)},
            -Double.MAX_VALUE,
            Double.MAX_VALUE,
            true),
        arguments(
            new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff},
            new double[] {Double.longBitsToDouble(0xffffffffL)},
            -Double.MAX_VALUE,
            Double.MAX_VALUE,
            true),
        arguments(
            new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff},
            new double[] {Double.longBitsToDouble(0xffffffffffL)},
            -Double.MAX_VALUE,
            Double.MAX_VALUE,
            true),
        arguments(
            new byte[] {
              (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff
            },
            new double[] {Double.longBitsToDouble(0xffffffffffffL)},
            -Double.MAX_VALUE,
            Double.MAX_VALUE,
            true),
        arguments(
            new byte[] {
              (byte) 0xff,
              (byte) 0xff,
              (byte) 0xff,
              (byte) 0xff,
              (byte) 0xff,
              (byte) 0xff,
              (byte) 0xff
            },
            new double[] {Double.longBitsToDouble(0xffffffffffffffL)},
            -Double.MAX_VALUE,
            Double.MAX_VALUE,
            true),
        arguments(
            new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1},
            new double[] {0.0, Double.longBitsToDouble(0x010101)},
            -Double.MAX_VALUE,
            Double.MAX_VALUE,
            true));
  }

  @ParameterizedTest
  @MethodSource("bytes2doublesTestCases")
  void testArrayConversion_bytes2doubles(
      byte[] input, double[] expected, double min, double max, boolean allowNan) {
    Function<byte[], double[]> fn = getDoublePrimitiveArray(min, max, allowNan);
    assertThat(fn.apply(input)).isEqualTo(expected);
  }

  static Stream<Arguments> intsRoundTripTestCases() {
    return Stream.of(
        arguments(new int[] {1, 2, 3, 0, 1, 2, 3, 41037219}),
        arguments(new int[] {0, 0, 0, 0, 0, 0, 0, 0}),
        arguments(new int[] {0, 0, 0, 0, 0, 0, 0, 1}),
        arguments(new int[] {0, 0, 0, 0, 0, 0, 0, 2}),
        arguments(new int[] {0, 0, 0, 0, 0, 0, 0, 1 << 31}),
        arguments(new int[] {1 << 31, 0, 0, 0, 0, 0, 0, 1 >> 31}));
  }

  @ParameterizedTest
  @MethodSource("intsRoundTripTestCases")
  void testRoundTrip_ints(int[] numbers) {
    assertThat(bytesToInts.apply(intsToBytes.apply(numbers))).isEqualTo(numbers);
  }

  static Stream<Arguments> longsRoundTripTestCases() {
    return Stream.of(
        arguments(new long[] {1, 2, 3, 0, 1, 2, 3, 41037219}),
        arguments(new long[] {0, 0, 0, 0, 0, 0, 0, 0}),
        arguments(new long[] {0, 0, 0, 0, 0, 0, 0, 1}),
        arguments(new long[] {0, 0, 0, 0, 0, 0, 0, 2}),
        arguments(new long[] {0, 0, 0, 0, 0, 0, 0, 1L << 63}),
        arguments(new long[] {1L << 63, 0, 0, 0, 0, 0, 0, 1}));
  }

  @ParameterizedTest
  @MethodSource("longsRoundTripTestCases")
  void testRoundTrip_longs(long[] numbers) {
    assertThat(bytesToLongs.apply(longsToBytes.apply(numbers))).isEqualTo(numbers);
  }

  static Stream<Arguments> shortsRoundTripTestCases() {
    return Stream.of(
        arguments(new short[] {1, 2, 3, 0, 1, 2, 3, 12313}),
        arguments(new short[] {0, 0, 0, 0, 0, 0, 0, 0}),
        arguments(new short[] {0, 0, 0, 0, 0, 0, 0, 1}),
        arguments(new short[] {0, 0, 0, 0, 0, 0, 0, 2}),
        arguments(new short[] {0, 0, 0, 0, 0, 0, 0, 32767}),
        arguments(new short[] {32767, 0, 0, 0, 0, 0, 0, 1}));
  }

  @ParameterizedTest
  @MethodSource("shortsRoundTripTestCases")
  void testRoundTrip_shorts(short[] numbers) {
    assertThat(bytesToShorts.apply(shortsToBytes.apply(numbers))).isEqualTo(numbers);
  }

  static Stream<Arguments> charsRoundTripTestCases() {
    return Stream.of(
        arguments(new char[] {1, 2, 3, 0, 1, 2, 3, 12313}),
        arguments(new char[] {0, 0, 0, 0, 0, 0, 0, 0}),
        arguments(new char[] {0, 0, 0, 0, 0, 0, 0, 1}),
        arguments(new char[] {0, 0, 0, 0, 0, 0, 0, 2}),
        arguments(new char[] {0, 0, 0, 0, 0, 0, 0, 32767}),
        arguments(new char[] {32767, 0, 0, 0, 0, 0, 0, 1}));
  }

  @ParameterizedTest
  @MethodSource("charsRoundTripTestCases")
  void testRoundTrip_chars(char[] numbers) {
    assertThat(bytesToChars.apply(charsToBytes.apply(numbers))).isEqualTo(numbers);
  }

  static Stream<Arguments> booleansRoundTripTestCases() {
    return Stream.of(
        arguments(new boolean[] {true}),
        arguments(new boolean[] {false}),
        arguments(new boolean[] {true, false}),
        arguments(new boolean[] {false, true}),
        arguments(new boolean[] {true, true}),
        arguments(new boolean[] {false, false}),
        arguments(new boolean[] {true, true, false}));
  }

  @ParameterizedTest
  @MethodSource("booleansRoundTripTestCases")
  void testRoundTrip_booleans(boolean[] numbers) {
    assertThat(bytesToBooleans.apply(booleansToBytes.apply(numbers))).isEqualTo(numbers);
  }

  static Stream<Arguments> floatsRoundTripTestCases() {
    return Stream.of(
        arguments(new float[] {1.0f, 2.0f, 3.0f, 0.0f, 1.0f, 2.0f, 3.0f, 12313.0f}),
        arguments(
            new float[] {
              Float.MIN_VALUE,
              Float.MAX_VALUE,
              0.0f,
              -0.0f,
              Float.POSITIVE_INFINITY,
              Float.NEGATIVE_INFINITY,
              Float.NaN
            }));
  }

  @ParameterizedTest
  @MethodSource("floatsRoundTripTestCases")
  void testRoundTrip_floats(float[] numbers) {
    assertThat(bytesToFloats.apply(floatsToBytes.apply(numbers))).isEqualTo(numbers);
  }

  static Stream<Arguments> doublesRoundTripTestCases() {
    return Stream.of(
        arguments(new double[] {1, 2, 3, 4, 5}),
        arguments(
            new double[] {
              Double.MIN_VALUE,
              Double.MAX_VALUE,
              0.0,
              -0.0,
              Double.POSITIVE_INFINITY,
              Double.NEGATIVE_INFINITY,
              Double.NaN
            }));
  }

  @ParameterizedTest
  @MethodSource("doublesRoundTripTestCases")
  void testRoundTrip_doubles(double[] numbers) {
    assertThat(bytesToDoubles.apply(doublesToBytes.apply(numbers))).isEqualTo(numbers);
  }

  static Stream<Arguments> bytesRoundTripTestCases() {
    return Stream.of(
        arguments(new byte[] {1, 2, 3, 4, 5}),
        arguments(new byte[] {Byte.MIN_VALUE, Byte.MAX_VALUE, 0, -0, 1, -1, 127, -128}));
  }

  @ParameterizedTest
  @MethodSource("bytesRoundTripTestCases")
  void testRoundTrip_bytes(byte[] numbers) {
    assertThat(libfuzzerBytesToBytes.apply(bytesToLibfuzzerBytes.apply(numbers)))
        .isEqualTo(numbers);
  }
}
