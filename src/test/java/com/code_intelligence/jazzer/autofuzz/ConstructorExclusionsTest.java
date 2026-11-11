/*
 * Copyright 2026 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.autofuzz;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.util.Collections;
import java.util.Random;
import org.junit.Test;

public class ConstructorExclusionsTest {
  private static final AccessibleObjectLookup PUBLIC_LOOKUP = new AccessibleObjectLookup(null);

  public static class MultipleConstructors {
    public MultipleConstructors() {}

    public MultipleConstructors(int value) {}

    public MultipleConstructors(String value) {}
  }

  @Test
  public void defaultsDoNotExcludeConstructors() throws NoSuchMethodException {
    ConstructorExclusions exclusions = ConstructorExclusions.empty();

    assertFalse(exclusions.isExcluded(MultipleConstructors.class.getConstructor(int.class)));
  }

  @Test
  public void userExcludeMatchesExactConstructorOnly() throws NoSuchMethodException {
    ConstructorExclusions exclusions =
        ConstructorExclusions.from(
            Collections.singletonList(
                "com.code_intelligence.jazzer.autofuzz.ConstructorExclusionsTest"
                    + "$MultipleConstructors::new(int)"),
            PUBLIC_LOOKUP);

    assertTrue(exclusions.isExcluded(MultipleConstructors.class.getConstructor(int.class)));
    assertFalse(exclusions.isExcluded(MultipleConstructors.class.getConstructor(String.class)));
    assertFalse(exclusions.isExcluded(MultipleConstructors.class.getConstructor()));
  }

  @Test
  public void userExcludeMatchesBigIntegerPrimeConstructorOnly() throws NoSuchMethodException {
    ConstructorExclusions exclusions =
        ConstructorExclusions.from(
            Collections.singletonList("java.math.BigInteger::new(int,int,java.util.Random)"),
            PUBLIC_LOOKUP);

    assertTrue(
        exclusions.isExcluded(BigInteger.class.getConstructor(int.class, int.class, Random.class)));
    assertFalse(exclusions.isExcluded(BigInteger.class.getConstructor(byte[].class)));
  }

  @Test(expected = IllegalArgumentException.class)
  public void rejectsMissingDescriptor() {
    ConstructorExclusions.from(
        Collections.singletonList(
            "com.code_intelligence.jazzer.autofuzz.ConstructorExclusionsTest"
                + "$MultipleConstructors::new"),
        PUBLIC_LOOKUP);
  }

  @Test(expected = IllegalArgumentException.class)
  public void rejectsCanonicalNestedClassName() {
    ConstructorExclusions.from(
        Collections.singletonList(
            "com.code_intelligence.jazzer.autofuzz.ConstructorExclusionsTest"
                + ".MultipleConstructors::new(int)"),
        PUBLIC_LOOKUP);
  }

  @Test(expected = IllegalArgumentException.class)
  public void rejectsGlobs() {
    ConstructorExclusions.from(Collections.singletonList("java.math.*::new(int)"), PUBLIC_LOOKUP);
  }

  @Test(expected = IllegalArgumentException.class)
  public void rejectsWhitespace() {
    ConstructorExclusions.from(
        Collections.singletonList(
            "com.code_intelligence.jazzer.autofuzz.ConstructorExclusionsTest"
                + "$MultipleConstructors::new(int )"),
        PUBLIC_LOOKUP);
  }

  @Test(expected = IllegalArgumentException.class)
  public void rejectsGenericTypes() {
    ConstructorExclusions.from(
        Collections.singletonList(
            "com.code_intelligence.jazzer.autofuzz.ConstructorExclusionsTest"
                + "$MultipleConstructors::new(java.util.List<java.lang.String>)"),
        PUBLIC_LOOKUP);
  }

  @Test
  public void missingConstructorErrorListsAvailableConstructors() {
    String reference =
        "com.code_intelligence.jazzer.autofuzz.ConstructorExclusionsTest"
            + "$MultipleConstructors::new(long)";

    try {
      ConstructorExclusions.from(Collections.singletonList(reference), PUBLIC_LOOKUP);
      fail("Expected an IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains(reference));
      assertTrue(e.getMessage().contains("Accessible constructors:"));
      assertTrue(e.getMessage().contains(MultipleConstructors.class.getName() + "::new(int)"));
    }
  }
}
