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

package com.code_intelligence.jazzer.autofuzz;

import static com.code_intelligence.jazzer.autofuzz.TestHelpers.consumeTestCase;

import java.util.Arrays;
import java.util.Objects;
import org.junit.Test;

public class InterfaceCreationTest {
  public interface InterfaceA {
    void foo();

    void bar();
  }

  public abstract static class ClassA1 implements InterfaceA {
    @Override
    public void foo() {}
  }

  public static class ClassB1 extends ClassA1 {
    int n;

    public ClassB1(int _n) {
      n = _n;
    }

    @Override
    public void bar() {}

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      ClassB1 classB1 = (ClassB1) o;
      return n == classB1.n;
    }

    @Override
    public int hashCode() {
      return Objects.hash(n);
    }
  }

  public static class ClassB2 implements InterfaceA {
    String s;

    public ClassB2(String _s) {
      s = _s;
    }

    @Override
    public void foo() {}

    @Override
    public void bar() {}

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      ClassB2 classB2 = (ClassB2) o;
      return Objects.equals(s, classB2.s);
    }

    @Override
    public int hashCode() {
      return Objects.hash(s);
    }
  }

  @Test
  public void testConsumeInterface() {
    consumeTestCase(
        InterfaceA.class,
        new ClassB1(5),
        "(com.code_intelligence.jazzer.autofuzz.InterfaceCreationTest.InterfaceA) new"
            + " com.code_intelligence.jazzer.autofuzz.InterfaceCreationTest.ClassB1(5)",
        Arrays.asList(
            (byte) 1, // do not return null
            0, // pick ClassB1
            (byte) 1, // do not return null
            0, // pick first constructor
            5 // arg for ClassB1 constructor
            ));
    consumeTestCase(
        InterfaceA.class,
        new ClassB2("test"),
        "(com.code_intelligence.jazzer.autofuzz.InterfaceCreationTest.InterfaceA) new"
            + " com.code_intelligence.jazzer.autofuzz.InterfaceCreationTest.ClassB2(\"test\")",
        Arrays.asList(
            (byte) 1, // do not return null
            1, // pick ClassB2
            (byte) 1, // do not return null
            0, // pick first constructor
            (byte) 1, // do not return null
            8, // remaining bytes
            "test" // arg for ClassB2 constructor
            ));
  }
}
