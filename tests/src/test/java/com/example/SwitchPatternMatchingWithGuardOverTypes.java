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
