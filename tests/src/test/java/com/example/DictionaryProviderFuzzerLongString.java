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

package com.example;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.jazzer.mutation.annotation.DictionaryProvider;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.WithUtf8Length;
import java.util.stream.Stream;

public class DictionaryProviderFuzzerLongString {

  public static Stream<?> myDict() {
    return Stream.of(
        repeat("0123456789abcdef", 50),
        repeat("sitting duck suprime", 53),
        // We can mix all kinds of values in the same dictionary.
        // Each mutator only takes the values it can use.
        123);
  }

  @FuzzTest
  // Just propagate the dictionary to all types of the fuzz test method that can use it.
  // We could also only annotate the String parameters, but this is easier.
  @DictionaryProvider(
      value = {"myDict"},
      // Don't want to wait, force String mutators to use dictionary values every other time.
      pInv = 2)
  public static void fuzzerTestOneInput(
      @NotNull @WithUtf8Length(max = 10000) String data,
      @NotNull @WithUtf8Length(max = 10000) String data2) {
    /*
     * libFuzzer's table of recent compares only allows 64 bytes, so asking the fuzzer to construct
     * these long strings would run for a very very long time without finding them. With a
     * DictionaryProvider this problem is trivial, because we can directly provide these long strings to
     * the fuzzer, and also force that they are used more often by setting pInv to a low value.
     */
    if (data.equals(repeat("0123456789abcdef", 50))
        && data2.equals(repeat("sitting duck suprime", 53))) {
      throw new FuzzerSecurityIssueLow("Found the long string!");
    }
  }

  private static String repeat(String str, int count) {
    StringBuilder sb = new StringBuilder(str.length() * count);
    for (int i = 0; i < count; i++) {
      sb.append(str);
    }
    return sb.toString();
  }
}
