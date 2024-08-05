/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
