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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.DictionaryEntries;
import com.code_intelligence.jazzer.junit.DictionaryFile;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class DictionaryFuzzTests {
  // Generated via:
  // printf 'a_53Cr"3T_fl4G' | openssl dgst -binary -sha256 | openssl base64 -A
  // Luckily the fuzzer can't read comments ;-)
  private static final byte[] FLAG_SHA256 =
      Base64.getDecoder().decode("vCLInoVuMxJonT4UKjsMl0LPXTowkYS7t0uBpw0pRo8=");

  @DictionaryEntries({"a_53Cr\"3T_fl4G"})
  @FuzzTest
  public void inlineTest(FuzzedDataProvider data)
      throws NoSuchAlgorithmException, TestSuccessfulException {
    String s = data.consumeRemainingAsString();
    byte[] hash = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
    if (MessageDigest.isEqual(hash, FLAG_SHA256)) {
      throw new TestSuccessfulException("error found");
    }
  }

  @DictionaryFile(resourcePath = "test.dict")
  @FuzzTest
  public void fileTest(FuzzedDataProvider data)
      throws NoSuchAlgorithmException, TestSuccessfulException {
    String s = data.consumeRemainingAsString();
    byte[] hash = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
    if (MessageDigest.isEqual(hash, FLAG_SHA256)) {
      throw new TestSuccessfulException("error found");
    }
  }

  /**
   * This test uses multiple dictionaries, one of which is loaded on-the-fly. The other two are
   * loaded from files. The test will only succeed if entries from all three dictionaries have been
   * used at least once to generate fuzzer data input completely.
   */
  private static final byte[] ON_THE_FLY_FLAG_SHA256 =
      Base64.getDecoder().decode("YgF0VLwI07ls++qMJ/Ptmc9Q7xlIErMXXXK1enpNqKw=");

  private static final byte[] FILE_TEST2_FLAG_SHA256 =
      Base64.getDecoder().decode("nIQ780j1iRJbOouWMvwhmS63i5lcHlhBf780CFmXvdc=");
  private static final byte[] FILE_TEST3_FLAG_SHA256 =
      Base64.getDecoder().decode("JR9EuaWZ5hyEHy2Ynfh1KCLI60UL8evAYYTAoJhCcaY=");

  private static boolean onTheFlyDictionaryFound =
      false; // =o1pPß?1bHJAfas => YgF0VLwI07ls++qMJ/Ptmc9Q7xlIErMXXXK1enpNqKw=
  private static boolean fileTest2DictFound =
      false; // 0Z1o21ka => nIQ780j1iRJbOouWMvwhmS63i5lcHlhBf780CFmXvdc=
  private static boolean fileTest3DictFound =
      false; // A)716&=Ko => JR9EuaWZ5hyEHy2Ynfh1KCLI60UL8evAYYTAoJhCcaY=

  @DictionaryEntries("=o1pPß?1bHJAfas")
  @DictionaryFile(resourcePath = "test2.dict")
  @DictionaryFile(resourcePath = "/com/example/test3.dict")
  @FuzzTest
  public void mixedTest(FuzzedDataProvider data)
      throws NoSuchAlgorithmException, TestSuccessfulException {
    String s = data.consumeRemainingAsString();
    byte[] hash = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
    if (MessageDigest.isEqual(hash, ON_THE_FLY_FLAG_SHA256)) {
      onTheFlyDictionaryFound = true;
    } else if (MessageDigest.isEqual(hash, FILE_TEST2_FLAG_SHA256)) {
      fileTest2DictFound = true;
    } else if (MessageDigest.isEqual(hash, FILE_TEST3_FLAG_SHA256)) {
      fileTest3DictFound = true;
    }
    if (onTheFlyDictionaryFound && fileTest2DictFound && fileTest3DictFound) {
      throw new TestSuccessfulException("error found");
    }
  }
}
