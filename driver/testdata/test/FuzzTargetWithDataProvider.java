// Copyright 2021 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package test;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.stream.Collectors;

class FuzzTargetWithDataProvider {
  public static <T extends Comparable<T>> void assertEqual(T a, T b) {
    if (a.compareTo(b) != 0) {
      throw new IllegalArgumentException("Expected: " + a + ", got: " + b);
    }
  }

  public strictfp static void fuzzerTestOneInput(FuzzedDataProvider data) {
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

    assertEqual(true,
        Arrays.equals(new boolean[] {false, false, true, false, true}, data.consumeBooleans(5)));
    assertEqual(true,
        Arrays.equals(new long[] {0x0123456789abdcefL, 0xfedcba9876543210L}, data.consumeLongs(2)));

    assertEqual((float) 0.28969181, data.consumeProbabilityFloat());
    assertEqual(0.086814121166605432, data.consumeProbabilityDouble());
    assertEqual((float) 0.30104411, data.consumeProbabilityFloat());
    assertEqual(0.96218831486039413, data.consumeProbabilityDouble());

    assertEqual((float) -2.8546307e+38, data.consumeRegularFloat());
    assertEqual(8.0940194040236032e+307, data.consumeRegularDouble());
    assertEqual((float) 271.49084, data.consumeRegularFloat((float) 123.0, (float) 777.0));
    assertEqual(30.859126145478349, data.consumeRegularDouble(13.37, 31.337));

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
}
