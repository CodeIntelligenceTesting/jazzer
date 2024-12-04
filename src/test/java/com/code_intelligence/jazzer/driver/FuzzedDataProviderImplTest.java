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

package com.code_intelligence.jazzer.driver;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Arrays;
import java.util.stream.Collectors;

public class FuzzedDataProviderImplTest {
  public static void main(String[] args) {
    try (FuzzedDataProviderImpl fuzzedDataProvider =
        FuzzedDataProviderImpl.withJavaData(INPUT_BYTES)) {
      verifyFuzzedDataProvider(fuzzedDataProvider);
    }
  }

  private static strictfp void verifyFuzzedDataProvider(FuzzedDataProvider data) {
    assertEqual(true, data.consumeBoolean());

    assertEqual((byte) 0x7F, data.consumeByte());
    assertEqual((byte) 0x14, data.consumeByte((byte) 0x12, (byte) 0x22));

    assertEqual(0x12345678, data.consumeInt());
    assertEqual(-0x12345600, data.consumeInt(-0x12345678, -0x12345600));
    assertEqual(0x12345679, data.consumeInt(0x12345678, 0x12345679));

    assertEqual(true, Arrays.equals(new byte[] {0x01, 0x02}, data.consumeBytes(2)));

    assertEqual("jazzer", data.consumeString(6));
    assertEqual("ja\u0000zer", data.consumeString(6));
    assertEqual("€ß", data.consumeString(2));

    assertEqual("jazzer", data.consumeAsciiString(6));
    assertEqual("ja\u0000zer", data.consumeAsciiString(6));
    assertEqual("\u0062\u0002\u002C\u0043\u001F", data.consumeAsciiString(5));

    assertEqual(
        true,
        Arrays.equals(new boolean[] {false, false, true, false, true}, data.consumeBooleans(5)));
    assertEqual(
        true,
        Arrays.equals(new long[] {0x0123456789abdcefL, 0xfedcba9876543210L}, data.consumeLongs(2)));

    assertAtLeastAsPrecise((float) 0.28969181, data.consumeProbabilityFloat());
    assertAtLeastAsPrecise(0.086814121166605432, data.consumeProbabilityDouble());
    assertAtLeastAsPrecise((float) 0.30104411, data.consumeProbabilityFloat());
    assertAtLeastAsPrecise(0.96218831486039413, data.consumeProbabilityDouble());

    assertAtLeastAsPrecise((float) -2.8546307e+38, data.consumeRegularFloat());
    assertAtLeastAsPrecise(8.0940194040236032e+307, data.consumeRegularDouble());
    assertAtLeastAsPrecise(
        (float) 271.49084, data.consumeRegularFloat((float) 123.0, (float) 777.0));
    assertAtLeastAsPrecise(30.859126145478349, data.consumeRegularDouble(13.37, 31.337));

    assertEqual((float) 0.0, data.consumeFloat());
    assertEqual((float) -0.0, data.consumeFloat());
    assertEqual(Float.POSITIVE_INFINITY, data.consumeFloat());
    assertEqual(Float.NEGATIVE_INFINITY, data.consumeFloat());
    assertEqual(true, Float.isNaN(data.consumeFloat()));
    assertEqual(Float.MIN_VALUE, data.consumeFloat());
    assertEqual(-Float.MIN_VALUE, data.consumeFloat());
    assertEqual(Float.MIN_NORMAL, data.consumeFloat());
    assertEqual(-Float.MIN_NORMAL, data.consumeFloat());
    assertEqual(Float.MAX_VALUE, data.consumeFloat());
    assertEqual(-Float.MAX_VALUE, data.consumeFloat());

    assertEqual(0.0, data.consumeDouble());
    assertEqual(-0.0, data.consumeDouble());
    assertEqual(Double.POSITIVE_INFINITY, data.consumeDouble());
    assertEqual(Double.NEGATIVE_INFINITY, data.consumeDouble());
    assertEqual(true, Double.isNaN(data.consumeDouble()));
    assertEqual(Double.MIN_VALUE, data.consumeDouble());
    assertEqual(-Double.MIN_VALUE, data.consumeDouble());
    assertEqual(Double.MIN_NORMAL, data.consumeDouble());
    assertEqual(-Double.MIN_NORMAL, data.consumeDouble());
    assertEqual(Double.MAX_VALUE, data.consumeDouble());
    assertEqual(-Double.MAX_VALUE, data.consumeDouble());

    int[] array = {0, 1, 2, 3, 4};
    assertEqual(4, data.pickValue(array));
    assertEqual(2, (int) data.pickValue(Arrays.stream(array).boxed().toArray()));
    assertEqual(3, data.pickValue(Arrays.stream(array).boxed().collect(Collectors.toList())));
    assertEqual(2, data.pickValue(Arrays.stream(array).boxed().collect(Collectors.toSet())));

    // Buffer is almost depleted at this point.
    assertEqual(7, data.remainingBytes());
    assertEqual(true, Arrays.equals(new long[0], data.consumeLongs(3)));
    assertEqual(7, data.remainingBytes());
    assertEqual(true, Arrays.equals(new int[] {0x12345678}, data.consumeInts(3)));
    assertEqual(3, data.remainingBytes());
    assertEqual(0x123456L, data.consumeLong());

    // Buffer has been fully consumed at this point
    assertEqual(0, data.remainingBytes());
    assertEqual(0, data.consumeInt());
    assertEqual(0.0, data.consumeDouble());
    assertEqual(-13.37, data.consumeRegularDouble(-13.37, 31.337));
    assertEqual(true, Arrays.equals(new byte[0], data.consumeBytes(4)));
    assertEqual(true, Arrays.equals(new long[0], data.consumeLongs(4)));
    assertEqual("", data.consumeRemainingAsAsciiString());
    assertEqual("", data.consumeRemainingAsString());
    assertEqual("", data.consumeAsciiString(100));
    assertEqual("", data.consumeString(100));
  }

  private static void assertAtLeastAsPrecise(double expected, double actual) {
    BigDecimal exactExpected = BigDecimal.valueOf(expected);
    BigDecimal roundedActual =
        BigDecimal.valueOf(actual).setScale(exactExpected.scale(), RoundingMode.HALF_UP);
    if (!exactExpected.equals(roundedActual)) {
      throw new IllegalArgumentException(
          String.format("Expected: %s, got: %s (rounded: %s)", expected, actual, roundedActual));
    }
  }

  private static <T extends Comparable<T>> void assertEqual(T a, T b) {
    if (a.compareTo(b) != 0) {
      throw new IllegalArgumentException("Expected: " + a + ", got: " + b);
    }
  }

  private static final byte[] INPUT_BYTES =
      new byte[] {
        // Bytes read from the start
        0x01,
        0x02, // consumeBytes(2): {0x01, 0x02}
        'j',
        'a',
        'z',
        'z',
        'e',
        'r', // consumeString(6): "jazzer"
        'j',
        'a',
        0x00,
        'z',
        'e',
        'r', // consumeString(6): "ja\u0000zer"
        (byte) 0xE2,
        (byte) 0x82,
        (byte) 0xAC,
        (byte) 0xC3,
        (byte) 0x9F, // consumeString(2): "€ẞ"
        'j',
        'a',
        'z',
        'z',
        'e',
        'r', // consumeAsciiString(6): "jazzer"
        'j',
        'a',
        0x00,
        'z',
        'e',
        'r', // consumeAsciiString(6): "ja\u0000zer"
        (byte) 0xE2,
        (byte) 0x82,
        (byte) 0xAC,
        (byte) 0xC3,
        (byte) 0x9F, // consumeAsciiString(5): "\u0062\u0002\u002C\u0043\u001F"
        0,
        0,
        1,
        0,
        1, // consumeBooleans(5): { false, false, true, false, true }
        (byte) 0xEF,
        (byte) 0xDC,
        (byte) 0xAB,
        (byte) 0x89,
        0x67,
        0x45,
        0x23,
        0x01,
        0x10,
        0x32,
        0x54,
        0x76,
        (byte) 0x98,
        (byte) 0xBA,
        (byte) 0xDC,
        (byte) 0xFE,
        // consumeLongs(2): { 0x0123456789ABCDEF, 0xFEDCBA9876543210 }

        0x78,
        0x56,
        0x34,
        0x12, // consumeInts(3): { 0x12345678 }
        0x56,
        0x34,
        0x12, // consumeLong():

        // Bytes read from the end
        0x02,
        0x03,
        0x02,
        0x04, // 4x pickValue in array with five elements
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90,
        0x12,
        0x34,
        0x56,
        0x78, // consumed but unused by consumeDouble()
        10, // -max for next consumeDouble
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90,
        0x12,
        0x34,
        0x56,
        0x78, // consumed but unused by consumeDouble()
        9, // max for next consumeDouble
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90,
        0x12,
        0x34,
        0x56,
        0x78, // consumed but unused by consumeDouble()
        8, // -min for next consumeDouble
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90,
        0x12,
        0x34,
        0x56,
        0x78, // consumed but unused by consumeDouble()
        7, // min for next consumeDouble
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90,
        0x12,
        0x34,
        0x56,
        0x78, // consumed but unused by consumeDouble()
        6, // -denorm_min for next consumeDouble
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90,
        0x12,
        0x34,
        0x56,
        0x78, // consumed but unused by consumeDouble()
        5, // denorm_min for next consumeDouble
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90,
        0x12,
        0x34,
        0x56,
        0x78, // consumed but unused by consumeDouble()
        4, // NaN for next consumeDouble
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90,
        0x12,
        0x34,
        0x56,
        0x78, // consumed but unused by consumeDouble()
        3, // -infinity for next consumeDouble
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90,
        0x12,
        0x34,
        0x56,
        0x78, // consumed but unused by consumeDouble()
        2, // infinity for next consumeDouble
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90,
        0x12,
        0x34,
        0x56,
        0x78, // consumed but unused by consumeDouble()
        1, // -0.0 for next consumeDouble
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90,
        0x12,
        0x34,
        0x56,
        0x78, // consumed but unused by consumeDouble()
        0, // 0.0 for next consumeDouble
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90, // consumed but unused by consumeFloat()
        10, // -max for next consumeFloat
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90, // consumed but unused by consumeFloat()
        9, // max for next consumeFloat
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90, // consumed but unused by consumeFloat()
        8, // -min for next consumeFloat
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90, // consumed but unused by consumeFloat()
        7, // min for next consumeFloat
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90, // consumed but unused by consumeFloat()
        6, // -denorm_min for next consumeFloat
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90, // consumed but unused by consumeFloat()
        5, // denorm_min for next consumeFloat
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90, // consumed but unused by consumeFloat()
        4, // NaN for next consumeFloat
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90, // consumed but unused by consumeFloat()
        3, // -infinity for next consumeFloat
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90, // consumed but unused by consumeFloat()
        2, // infinity for next consumeFloat
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90, // consumed but unused by consumeFloat()
        1, // -0.0 for next consumeFloat
        0x12,
        0x34,
        0x56,
        0x78,
        (byte) 0x90, // consumed but unused by consumeFloat()
        0, // 0.0 for next consumeFloat
        (byte) 0x88,
        (byte) 0xAB,
        0x61,
        (byte) 0xCB,
        0x32,
        (byte) 0xEB,
        0x30,
        (byte) 0xF9,
        // consumeDouble(13.37, 31.337): 30.859126145478349 (small range)
        0x51,
        (byte) 0xF6,
        0x1F,
        0x3A, // consumeFloat(123.0, 777.0): 271.49084 (small range)
        0x11,
        0x4D,
        (byte) 0xFD,
        0x54,
        (byte) 0xD6,
        0x3D,
        0x43,
        0x73,
        0x39,
        // consumeRegularDouble(): 8.0940194040236032e+307
        0x16,
        (byte) 0xCF,
        0x3D,
        0x29,
        0x4A, // consumeRegularFloat(): -2.8546307e+38
        0x61,
        (byte) 0xCB,
        0x32,
        (byte) 0xEB,
        0x30,
        (byte) 0xF9,
        0x51,
        (byte) 0xF6,
        // consumeProbabilityDouble(): 0.96218831486039413
        0x1F,
        0x3A,
        0x11,
        0x4D, // consumeProbabilityFloat(): 0.30104411
        (byte) 0xFD,
        0x54,
        (byte) 0xD6,
        0x3D,
        0x43,
        0x73,
        0x39,
        0x16,
        // consumeProbabilityDouble(): 0.086814121166605432
        (byte) 0xCF,
        0x3D,
        0x29,
        0x4A, // consumeProbabilityFloat(): 0.28969181
        0x01, // consumeInt(0x12345678, 0x12345679): 0x12345679
        0x78, // consumeInt(-0x12345678, -0x12345600): -0x12345600
        0x78,
        0x56,
        0x34,
        0x12, // consumeInt(): 0x12345678
        0x02, // consumeByte(0x12, 0x22): 0x14
        0x7F, // consumeByte(): 0x7F
        0x01, // consumeBool(): true
      };
}
