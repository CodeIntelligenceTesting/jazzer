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

package com.code_intelligence.selffuzz.driver;

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.selffuzz.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.selffuzz.jazzer.driver.FuzzedDataProviderImpl;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

public class FuzzedDataProviderImplFuzzTest {
  @FuzzTest
  void fuzzedDataProviderTest(byte @NotNull [] buf) {
    try (FuzzedDataProviderImpl data = FuzzedDataProviderImpl.withJavaData(buf)) {
      List<Consumer<FuzzedDataProvider>> actionList = getActionList();

      while (data.remainingBytes() > 0) {
        Consumer<FuzzedDataProvider> action = data.pickValue(actionList);
        action.accept(data);
      }
    }
  }

  List<Consumer<FuzzedDataProvider>> getActionList() {
    return Collections.unmodifiableList(
        Arrays.asList(
            // clang-format off
            // clang-format would compress this into multiple functions per line which I think looks
            // worse
            this::testBoolean,
            this::testBooleans,
            this::testByte,
            this::testByteMinMax,
            this::testBytes,
            this::testRemainingAsBytes,
            this::testShort,
            this::testShortMinMax,
            this::testShorts,
            this::testInt,
            this::testIntMinMax,
            this::testInts,
            this::testLong,
            this::testLongMinMax,
            this::testLongs,
            this::testFloat,
            this::testRegularFloat,
            this::testRegularFloatMinMax,
            this::testProbabilityFloat,
            this::testDouble,
            this::testRegularDouble,
            this::testRegularDoubleMinMax,
            this::testProbabilityDouble,
            this::testChar,
            this::testConsumeCharMinMax,
            this::testCharNoSurrogates,
            this::testString,
            this::testRemainingAsString,
            this::testAsciiString,
            this::testRemainingAsAsciiString,
            this::testPickValueCollection,
            this::testPickValueArray,
            this::testPickValueBoolean,
            this::testPickValueByte,
            this::testPickValueShort,
            this::testPickValueInt,
            this::testPickValueLong,
            this::testPickValueDouble,
            this::testPickValueFloat,
            this::testPickValueChar,
            this::testPickValuesCollection,
            this::testPickValuesArray
            // clang-format on
            ));
  }

  void testBoolean(FuzzedDataProvider data) {
    data.consumeBoolean();
  }

  void testBooleans(FuzzedDataProvider data) {
    int length = data.consumeInt();
    if (length < 0) {
      return;
    }
    data.consumeBooleans(length);
  }

  void testByte(FuzzedDataProvider data) {
    data.consumeByte();
  }

  void testByteMinMax(FuzzedDataProvider data) {
    byte min = data.consumeByte();
    byte max = data.consumeByte();
    if (min > max) {
      return;
    }
    data.consumeByte(min, max);
  }

  void testBytes(FuzzedDataProvider data) {
    int length = data.consumeInt();
    if (length < 0) {
      return;
    }
    data.consumeBytes(length);
  }

  void testRemainingAsBytes(FuzzedDataProvider data) {
    data.consumeRemainingAsBytes();
  }

  void testShort(FuzzedDataProvider data) {
    data.consumeShort();
  }

  void testShortMinMax(FuzzedDataProvider data) {
    short min = data.consumeShort();
    short max = data.consumeShort();
    if (min > max) {
      return;
    }
    data.consumeShort(min, max);
  }

  void testShorts(FuzzedDataProvider data) {
    int length = data.consumeInt();
    if (length < 0) {
      return;
    }
    data.consumeShorts(length);
  }

  void testInt(FuzzedDataProvider data) {
    data.consumeInt();
  }

  void testIntMinMax(FuzzedDataProvider data) {
    int min = data.consumeInt();
    int max = data.consumeInt();
    if (min > max) {
      return;
    }
    data.consumeInt(min, max);
  }

  void testInts(FuzzedDataProvider data) {
    int length = data.consumeInt();
    if (length < 0) {
      return;
    }
    data.consumeInts(length);
  }

  void testLong(FuzzedDataProvider data) {
    data.consumeLong();
  }

  void testLongMinMax(FuzzedDataProvider data) {
    long min = data.consumeLong();
    long max = data.consumeLong();
    if (min > max) {
      return;
    }
    data.consumeLong(min, max);
  }

  void testLongs(FuzzedDataProvider data) {
    int length = data.consumeInt();
    if (length < 0) {
      return;
    }
    data.consumeLongs(length);
  }

  void testFloat(FuzzedDataProvider data) {
    data.consumeFloat();
  }

  void testRegularFloat(FuzzedDataProvider data) {
    float f = data.consumeRegularFloat();
    if (!Float.isFinite(f)) {
      throw new RuntimeException("regular float has invalid value");
    }
  }

  void testRegularFloatMinMax(FuzzedDataProvider data) {
    float min = data.consumeFloat();
    float max = data.consumeFloat();
    if (!Float.isFinite(min) || !Float.isFinite(max)) {
      return;
    }
    if (min > max) {
      return;
    }
    float f = data.consumeRegularFloat(min, max);
    if (!Float.isFinite(f)) {
      throw new RuntimeException("regular float has invalid value");
    }
    if (f < min) {
      throw new RuntimeException("output value is smaller than min");
    }
    if (f > max) {
      throw new RuntimeException("output value is larger than max");
    }
  }

  void testProbabilityFloat(FuzzedDataProvider data) {
    float f = data.consumeProbabilityFloat();
    if (f < 0.0 || f > 1.0) {
      throw new RuntimeException("probability float has value outside [0.0, 1.0]");
    }
  }

  void testDouble(FuzzedDataProvider data) {
    data.consumeDouble();
  }

  void testRegularDouble(FuzzedDataProvider data) {
    double d = data.consumeRegularDouble();
    if (!Double.isFinite(d)) {
      throw new RuntimeException("regular double has invalid value");
    }
  }

  void testRegularDoubleMinMax(FuzzedDataProvider data) {
    double min = data.consumeDouble();
    double max = data.consumeDouble();
    if (!Double.isFinite(min) || !Double.isFinite(max)) {
      return;
    }
    if (min > max) {
      return;
    }
    double d = data.consumeRegularDouble(min, max);
    if (!Double.isFinite(d)) {
      throw new RuntimeException("regular double has invalid value");
    }
    if (d < min) {
      throw new RuntimeException("output value is smaller than min");
    }
    if (d > max) {
      throw new RuntimeException("output value is larger than max");
    }
  }

  void testProbabilityDouble(FuzzedDataProvider data) {
    double d = data.consumeProbabilityDouble();
    if (d < 0.0 || d > 1.0) {
      throw new RuntimeException("probability double is outside [0.0, 1.0]");
    }
  }

  void testChar(FuzzedDataProvider data) {
    data.consumeChar();
  }

  void testConsumeCharMinMax(FuzzedDataProvider data) {
    char min = data.consumeChar();
    char max = data.consumeChar();
    if (min > max) {
      return;
    }
    data.consumeChar(min, max);
  }

  void testCharNoSurrogates(FuzzedDataProvider data) {
    char c = data.consumeCharNoSurrogates();
    if (Character.isSurrogate(c)) {
      throw new RuntimeException("character was a surrogate");
    }
  }

  void testString(FuzzedDataProvider data) {
    int length = data.consumeInt();
    if (length < 0) {
      return;
    }
    data.consumeString(length);
  }

  void testRemainingAsString(FuzzedDataProvider data) {
    data.consumeRemainingAsString();
  }

  void testAsciiString(FuzzedDataProvider data) {
    int length = data.consumeInt();
    if (length < 0) {
      return;
    }
    String s = data.consumeAsciiString(length);
    if (s.chars().anyMatch(c -> c >= 128)) {
      throw new RuntimeException("ascii string contains character outside ascii range");
    }
  }

  void testRemainingAsAsciiString(FuzzedDataProvider data) {
    data.consumeRemainingAsAsciiString();
  }

  void testPickValueCollection(FuzzedDataProvider data) {
    int length = data.consumeShort();
    if (length <= 0) {
      return;
    }
    ArrayList<Integer> collection = new ArrayList<>();
    for (int i = 0; i < length; i++) {
      collection.add(data.consumeInt());
    }

    data.pickValue(collection);
  }

  void testPickValueArray(FuzzedDataProvider data) {
    int length = data.consumeShort();
    if (length <= 0) {
      return;
    }
    Integer[] collection = new Integer[length];
    for (int i = 0; i < length; i++) {
      collection[i] = data.consumeInt();
    }
    data.pickValue(collection);
  }

  void testPickValueBoolean(FuzzedDataProvider data) {
    int length = data.consumeShort();
    if (length <= 0) {
      return;
    }
    boolean[] collection = new boolean[length];
    for (int i = 0; i < length; i++) {
      collection[i] = data.consumeBoolean();
    }
    data.pickValue(collection);
  }

  void testPickValueByte(FuzzedDataProvider data) {
    int length = data.consumeShort();
    if (length <= 0) {
      return;
    }
    byte[] collection = new byte[length];
    for (int i = 0; i < length; i++) {
      collection[i] = data.consumeByte();
    }
    data.pickValue(collection);
  }

  void testPickValueShort(FuzzedDataProvider data) {
    int length = data.consumeShort();
    if (length <= 0) {
      return;
    }
    short[] collection = new short[length];
    for (int i = 0; i < length; i++) {
      collection[i] = data.consumeShort();
    }
    data.pickValue(collection);
  }

  void testPickValueInt(FuzzedDataProvider data) {
    int length = data.consumeShort();
    if (length <= 0) {
      return;
    }
    int[] collection = new int[length];
    for (int i = 0; i < length; i++) {
      collection[i] = data.consumeInt();
    }
    data.pickValue(collection);
  }

  void testPickValueLong(FuzzedDataProvider data) {
    int length = data.consumeShort();
    if (length <= 0) {
      return;
    }
    long[] collection = new long[length];
    for (int i = 0; i < length; i++) {
      collection[i] = data.consumeLong();
    }
    data.pickValue(collection);
  }

  void testPickValueDouble(FuzzedDataProvider data) {
    int length = data.consumeShort();
    if (length <= 0) {
      return;
    }
    double[] collection = new double[length];
    for (int i = 0; i < length; i++) {
      collection[i] = data.consumeDouble();
    }
    data.pickValue(collection);
  }

  void testPickValueFloat(FuzzedDataProvider data) {
    int length = data.consumeShort();
    if (length <= 0) {
      return;
    }
    float[] collection = new float[length];
    for (int i = 0; i < length; i++) {
      collection[i] = data.consumeFloat();
    }
    data.pickValue(collection);
  }

  void testPickValueChar(FuzzedDataProvider data) {
    int length = data.consumeShort();
    if (length <= 0) {
      return;
    }
    char[] collection = new char[length];
    for (int i = 0; i < length; i++) {
      collection[i] = data.consumeChar();
    }
    data.pickValue(collection);
  }

  void testPickValuesCollection(FuzzedDataProvider data) {
    int length = data.consumeShort();
    if (length <= 0) {
      return;
    }
    int numValues = data.consumeShort();
    if (numValues > length) {
      return;
    }
    ArrayList<Integer> collection = new ArrayList<>();
    for (int i = 0; i < length; i++) {
      collection.add(data.consumeInt());
    }

    data.pickValues(collection, numValues);
  }

  void testPickValuesArray(FuzzedDataProvider data) {
    int length = data.consumeShort();
    if (length <= 0) {
      return;
    }
    int numValues = data.consumeShort();
    if (numValues > length) {
      return;
    }
    Integer[] collection = new Integer[length];

    for (int i = 0; i < length; i++) {
      collection[i] = data.consumeInt();
    }
    data.pickValues(collection, numValues);
  }
}
