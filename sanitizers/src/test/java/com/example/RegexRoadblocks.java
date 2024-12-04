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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import java.util.regex.Pattern;

public class RegexRoadblocks {
  // We accept arbitrary suffixes but not prefixes for the following reasons:
  // 1. The fuzzer will take much longer to match the exact length of the input than to satisfy the
  //    compare checks, which is what we really want to test.
  // 2. Accepting arbitrary prefixes could lead to tests passing purely due to ToC entries being
  //    emitted in arbitrary positions, but we want to ensure that compares are correctly reported
  //    including position hints.
  private static final Pattern LITERAL = Pattern.compile("foobarbaz.*");
  private static final Pattern QUOTED_LITERAL = Pattern.compile(Pattern.quote("jazzer_is_cool.*"));
  private static final Pattern CASE_INSENSITIVE_LITERAL =
      Pattern.compile("JaZzER!.*", Pattern.CASE_INSENSITIVE);
  private static final Pattern GROUP = Pattern.compile("(always).*");
  private static final Pattern ALTERNATIVE = Pattern.compile("(to_be|not_to_be).*");
  private static final Pattern SINGLE_LATIN1_CHAR_PROPERTY = Pattern.compile("[€].*");
  private static final Pattern MULTIPLE_LATIN1_CHAR_PROPERTY = Pattern.compile("[ẞÄ].*");
  private static final Pattern RANGE_LATIN1_CHAR_PROPERTY = Pattern.compile("[¢-¥].*");

  private static int run = 0;

  private static boolean matchedLiteral = false;
  private static boolean matchedQuotedLiteral = false;
  private static boolean matchedCaseInsensitiveLiteral = false;
  private static boolean matchedGroup = false;
  private static boolean matchedAlternative = false;
  private static boolean matchedSingleLatin1CharProperty = false;
  private static boolean matchedMultipleLatin1CharProperty = false;
  private static boolean matchedRangeLatin1CharProperty = false;

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    run++;
    String input = data.consumeRemainingAsString();

    if (!matchedLiteral && LITERAL.matcher(input).matches()) {
      System.out.println("Cleared LITERAL");
      matchedLiteral = true;
    } else if (!matchedQuotedLiteral && QUOTED_LITERAL.matcher(input).matches()) {
      System.out.println("Cleared QUOTED_LITERAL");
      matchedQuotedLiteral = true;
    } else if (!matchedCaseInsensitiveLiteral
        && CASE_INSENSITIVE_LITERAL.matcher(input).matches()) {
      System.out.println("Cleared CASE_INSENSITIVE_LITERAL");
      matchedCaseInsensitiveLiteral = true;
    } else if (!matchedGroup && GROUP.matcher(input).matches()) {
      System.out.println("Cleared GROUP");
      matchedGroup = true;
    } else if (!matchedAlternative && ALTERNATIVE.matcher(input).matches()) {
      System.out.println("Cleared ALTERNATIVE");
      matchedAlternative = true;
    } else if (!matchedSingleLatin1CharProperty
        && SINGLE_LATIN1_CHAR_PROPERTY.matcher(input).matches()) {
      System.out.println("Cleared SINGLE_LATIN1_CHAR_PROPERTY");
      matchedSingleLatin1CharProperty = true;
    } else if (!matchedMultipleLatin1CharProperty
        && MULTIPLE_LATIN1_CHAR_PROPERTY.matcher(input).matches()) {
      System.out.println("Cleared MULTIPLE_LATIN1_CHAR_PROPERTY");
      matchedMultipleLatin1CharProperty = true;
    } else if (!matchedRangeLatin1CharProperty
        && RANGE_LATIN1_CHAR_PROPERTY.matcher(input).matches()) {
      System.out.println("Cleared RANGE_LATIN1_CHAR_PROPERTY");
      matchedRangeLatin1CharProperty = true;
    }

    if (matchedLiteral
        && matchedQuotedLiteral
        && matchedCaseInsensitiveLiteral
        && matchedGroup
        && matchedAlternative
        && matchedSingleLatin1CharProperty
        && matchedMultipleLatin1CharProperty
        && matchedRangeLatin1CharProperty) {
      throw new FuzzerSecurityIssueLow("Fuzzer matched all regexes in " + run + " runs");
    }
  }
}
