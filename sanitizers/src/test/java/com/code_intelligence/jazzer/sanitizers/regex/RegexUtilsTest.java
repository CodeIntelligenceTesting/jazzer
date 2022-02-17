// Copyright 2022 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.sanitizers.regex;

import com.code_intelligence.jazzer.sanitizers.utils.RegexUtils;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.Assert;
import org.junit.Test;

public class RegexUtilsTest {
  @Test
  public void testPartialMatchScore() {
    assertPartialMatchLength("[ab][cd]", "", 0);
    assertPartialMatchLength("[ab][cd]", "c", 0);
    assertPartialMatchLength("[ab][cd]", "a", 1);
    assertPartialMatchLength("[ab][cd]", "b", 1);
    assertPartialMatchLength("[ab][cd]", "ab", 1);
    assertPartialMatchLength("[ab][cd]", "ac", 2);
    assertPartialMatchLength("[ab][cd]", "bd", 2);
  }

  @Test
  public void testModifiedPatternHasLimitedRepetitionCount() {
    assertPartialMatchLength("a{1,3}b", "", 0);
    assertPartialMatchLength("a{1,3}b", "a", 1);
    assertPartialMatchLength("a{1,3}b", "aa", 1);
    assertPartialMatchLength("a{1,3}b", "aaa", 1);
    assertPartialMatchLength("a{1,3}b", "ab", 2);
    assertPartialMatchLength("a{1,3}b", "abc", 2);

    assertPartialMatchLength("[ac]{1,3}b", "", 0);
    assertPartialMatchLength("[ac]{1,3}b", "a", 1);
    assertPartialMatchLength("[ac]{1,3}b", "aa", 1);
    assertPartialMatchLength("[ac]{1,3}b", "aaa", 1);
    assertPartialMatchLength("[ac]{1,3}b", "ab", 2);
    assertPartialMatchLength("[ac]{1,3}b", "abc", 2);

    assertPartialMatchLength("[ac]*b", "", 0);
    assertPartialMatchLength("[ac]*b", "a", 1);
    assertPartialMatchLength("[ac]*b", "aa", 1);
    assertPartialMatchLength("[ac]*b", "aaa", 1);
    assertPartialMatchLength("[ac]*b", "ab", 2);
    assertPartialMatchLength("[ac]*b", "abc", 2);
  }

  private static void assertPartialMatchLength(String pattern, String guess, int length) {
    Pattern originalPattern = Pattern.compile(pattern);
    System.err.println(originalPattern.pattern());
    System.err.println("Original:");
    RegexUtils.printPattern(originalPattern);
    Pattern modifiedPattern = RegexUtils.compileRewardPattern(originalPattern);
    System.err.println("Modified:");
    RegexUtils.printPattern(modifiedPattern);
    Matcher matcher = modifiedPattern.matcher(guess);
    Assert.assertTrue(matcher.matches());
    Assert.assertEquals(0, matcher.start());
    Assert.assertEquals(length, matcher.end());
  }
}
