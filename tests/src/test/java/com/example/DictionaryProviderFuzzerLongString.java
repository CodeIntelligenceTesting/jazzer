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

import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.jazzer.mutation.annotation.DictionaryProvider;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.WithSize;
import com.code_intelligence.jazzer.mutation.annotation.WithUtf8Length;
import java.util.List;
import java.util.stream.Stream;

public class DictionaryProviderFuzzerLongString {
  private static final String str00 = repeat("0123456789abcdef", 50);
  private static final String str01 = repeat("sitting duck suprime", 53);
  private static final String str10 = repeat("poa0189fbhBHOVBO781%", 30);
  private static final String unused = repeat("XdeadbeefX", 21);

  public static Stream<?> dict0() {
    return Stream.of(
        str00,
        str01,
        // We can mix all kinds of values in the same dictionary.
        // Each mutator only takes the values it can use.
        123,
        4567899999L);
  }

  public static Stream<?> dict1() {
    return Stream.of(str10);
  }

  public static Stream<?> emptyDict() {
    return Stream.of();
  }

  public static Stream<?> unusedDictionary() {
    return Stream.of(unused);
  }

  @FuzzTest
  // Just propagate the dictionary to all types of the fuzz test method that can use it.
  // Annotating individual String parameters is also possible.
  @DictionaryProvider(
      value = {"dict0"},
      // Here we use a very low probability for picking dictionary values.
      // It gets overwritten for some arguments below.
      pInv = 1000000000)
  public static void fuzzerTestOneInput(
      @NotNull
          // Extend the maximum length of the String so that the dictionary values can actually be
          // used
          @WithUtf8Length(max = 10000)
          // The String mutator for this argument will use "dict1" and "emptyDict" with pInv = 2
          // for all dictionary entries.
          @DictionaryProvider(
              value = {"emptyDict"},
              // Set pInv = 2 for the String mutator
              pInv = 2)
          String data00,

      // Identical annotations as for data00
      @NotNull
          @WithUtf8Length(max = 10000)
          @DictionaryProvider(
              value = {"emptyDict"},
              pInv = 2)
          String data01,

      // The String mutator, inside the List mutator for this argument will use "dict0" and
      // "dict1" with pInv = 2 for all dictionary entries.
      // Note that the String mutator is not directly annotated, and gets annotated because
      // @DictionaryProvider has PropertyConstraint.RECURSIVE
      @DictionaryProvider(
              value = {"dict1"},
              pInv = 2)
          @NotNull
          @WithSize(max = 2)
          List<@NotNull String> data1,

      // The String mutator for this argument will use entries from
      // @DictionaryProvider(value={"dict0"}, pInv = 1000000000), that get propagated here from the
      // method annotation.
      @NotNull String data2) {

    // This should only happen 2:1000000000 times.
    assertThat(data2.equals(str00)).isFalse();
    assertThat(data2.equals(str01)).isFalse();

    // Error: matched a long string from dictionary entry this variable was NOT annotated with.
    // This should never happen.
    assertThat(data00.equals(str10)).isFalse();
    assertThat(data00.equals(unused)).isFalse();
    assertThat(data01.equals(str10)).isFalse();
    assertThat(data01.equals(unused)).isFalse();
    assertThat(data1.equals(unused)).isFalse();
    assertThat(data2.equals(str10)).isFalse();
    assertThat(data2.equals(unused)).isFalse();

    /*
     * libFuzzer's table of recent compares only allows 64 bytes, so asking the fuzzer to construct
     * these long strings would run for a very very long time without finding them. However, with a
     * @DictionaryProvider this problem is trivial, because we can directly provide these long strings to
     * the fuzzer, and also force that they are used more often by setting pInv to a low value close to 2.
     */
    if (data00.equals(str00)
        && data01.equals(str01)
        && !data1.isEmpty()
        && data1.get(0).equals(str10)) {
      throw new FuzzerSecurityIssueLow("Found all long strings as expected");
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
