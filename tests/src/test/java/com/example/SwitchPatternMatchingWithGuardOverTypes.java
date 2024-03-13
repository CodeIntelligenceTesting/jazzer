/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import java.util.Objects;

public class SwitchPatternMatchingWithGuardOverTypes {
  public static class Employee {
    public String name;
    public int age;

    public Employee(String name, int age) {
      this.name = name;
      this.age = age;
    }

    public void setAge(int age) {
      this.age = age;
    }

    public void setName(String name) {
      this.name = name;
    }

    public String getName() {
      return name;
    }

    public int getAge() {
      return age;
    }
  }

  public enum Type {
    INTEGER_T,
    STRING_T,
    EMPLOYEE_T,
    NULL_T
  }

  static SwitchCoverageHelper cov = new SwitchCoverageHelper(4);

  @FuzzTest
  public void test(
      @NotNull Integer anInt,
      @NotNull String aString,
      @NotNull Employee anEmployee,
      @NotNull Type type) {
    if (cov.allBranchesCovered()) {
      throw new FuzzerSecurityIssueLow("All cases visited");
    }
    Object inp =
        switch (type) {
          case INTEGER_T -> anInt;
          case STRING_T -> aString;
          case EMPLOYEE_T -> anEmployee;
          case NULL_T -> null;
        };

    int ignored =
        switch (inp) {
          case Integer i -> {
            cov.coverCase(0);
            yield 0;
          }
          case String s -> {
            cov.coverCase(1);
            yield 1;
          }
          case Employee e when Objects.equals(e.name, "Robot 001") -> {
            cov.coverCase(2);
            yield 2;
          }
          case null -> {
            cov.coverCase(3);
            yield 3;
          }
          default -> -10;
        };
  }
}
