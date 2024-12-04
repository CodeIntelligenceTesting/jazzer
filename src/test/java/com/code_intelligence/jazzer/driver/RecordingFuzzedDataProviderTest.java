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

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.LongStream;
import org.junit.Assert;
import org.junit.Test;

public class RecordingFuzzedDataProviderTest {
  @Test
  public void testRecordingFuzzedDataProvider() throws IOException {
    FuzzedDataProvider mockData = new MockFuzzedDataProvider();
    String referenceResult = sampleFuzzTarget(mockData);

    FuzzedDataProvider recordingMockData =
        RecordingFuzzedDataProvider.makeFuzzedDataProviderProxy(mockData);
    Assert.assertEquals(referenceResult, sampleFuzzTarget(recordingMockData));

    String cannedMockDataString =
        RecordingFuzzedDataProvider.serializeFuzzedDataProviderProxy(recordingMockData);
    FuzzedDataProvider cannedMockData = new CannedFuzzedDataProvider(cannedMockDataString);
    Assert.assertEquals(referenceResult, sampleFuzzTarget(cannedMockData));
  }

  private String sampleFuzzTarget(FuzzedDataProvider data) {
    StringBuilder result = new StringBuilder();
    result.append(data.consumeString(10));
    int[] ints = data.consumeInts(5);
    result.append(Arrays.stream(ints).mapToObj(Integer::toString).collect(Collectors.joining(",")));
    result.append(data.pickValue(ints));
    result.append(data.consumeString(20));
    result.append(
        data.pickValues(Arrays.stream(ints).boxed().collect(Collectors.toSet()), 5).stream()
            .map(Integer::toHexString)
            .collect(Collectors.joining(",")));
    result.append(data.remainingBytes());
    return result.toString();
  }

  private static final class MockFuzzedDataProvider implements FuzzedDataProvider {
    @Override
    public boolean consumeBoolean() {
      return true;
    }

    @Override
    public boolean[] consumeBooleans(int maxLength) {
      return new boolean[] {false, true};
    }

    @Override
    public byte consumeByte() {
      return 2;
    }

    @Override
    public byte consumeByte(byte min, byte max) {
      return max;
    }

    @Override
    public short consumeShort() {
      return 2;
    }

    @Override
    public short consumeShort(short min, short max) {
      return min;
    }

    @Override
    public short[] consumeShorts(int maxLength) {
      return new short[] {2, 4, 7};
    }

    @Override
    public int consumeInt() {
      return 5;
    }

    @Override
    public int consumeInt(int min, int max) {
      return max;
    }

    @Override
    public int[] consumeInts(int maxLength) {
      return IntStream.range(0, maxLength).toArray();
    }

    @Override
    public long consumeLong() {
      return 42;
    }

    @Override
    public long consumeLong(long min, long max) {
      return min;
    }

    @Override
    public long[] consumeLongs(int maxLength) {
      return LongStream.range(0, maxLength).toArray();
    }

    @Override
    public float consumeFloat() {
      return Float.NaN;
    }

    @Override
    public float consumeRegularFloat() {
      return 0.3f;
    }

    @Override
    public float consumeRegularFloat(float min, float max) {
      return min;
    }

    @Override
    public float consumeProbabilityFloat() {
      return 0.2f;
    }

    @Override
    public double consumeDouble() {
      return Double.NaN;
    }

    @Override
    public double consumeRegularDouble(double min, double max) {
      return max;
    }

    @Override
    public double consumeRegularDouble() {
      return Math.PI;
    }

    @Override
    public double consumeProbabilityDouble() {
      return 0.5;
    }

    @Override
    public char consumeChar() {
      return 'C';
    }

    @Override
    public char consumeChar(char min, char max) {
      return min;
    }

    @Override
    public char consumeCharNoSurrogates() {
      return 'C';
    }

    @Override
    public String consumeAsciiString(int maxLength) {
      return "foobar";
    }

    @Override
    public String consumeString(int maxLength) {
      return "foo€ä";
    }

    @Override
    public String consumeRemainingAsAsciiString() {
      return "foobar";
    }

    @Override
    public String consumeRemainingAsString() {
      return "foobar";
    }

    @Override
    public byte[] consumeBytes(int maxLength) {
      return new byte[maxLength];
    }

    @Override
    public byte[] consumeRemainingAsBytes() {
      return new byte[] {1};
    }

    @Override
    public int remainingBytes() {
      return 1;
    }
  }
}
