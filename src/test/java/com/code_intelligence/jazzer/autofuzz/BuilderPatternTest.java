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

class Employee {
  private final String firstName;
  private final String lastName;
  private final String jobTitle;
  private final int age;

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    Employee hero = (Employee) o;
    return age == hero.age
        && Objects.equals(firstName, hero.firstName)
        && Objects.equals(lastName, hero.lastName)
        && Objects.equals(jobTitle, hero.jobTitle);
  }

  @Override
  public int hashCode() {
    return Objects.hash(firstName, lastName, jobTitle, age);
  }

  private Employee(Builder builder) {
    this.jobTitle = builder.jobTitle;
    this.firstName = builder.firstName;
    this.lastName = builder.lastName;
    this.age = builder.age;
  }

  public static class Builder {
    private final String firstName;
    private final String lastName;
    private String jobTitle;
    private int age;

    public Builder(String firstName, String lastName) {
      this.firstName = firstName;
      this.lastName = lastName;
    }

    public Builder withAge(int age) {
      this.age = age;
      return this;
    }

    public Builder withJobTitle(String jobTitle) {
      this.jobTitle = jobTitle;
      return this;
    }

    public Employee build() {
      return new Employee(this);
    }
  }
}

public class BuilderPatternTest {
  @Test
  public void testBuilderPattern() {
    consumeTestCase(
        new Employee.Builder("foo", "bar").withAge(20).withJobTitle("baz").build(),
        "new com.code_intelligence.jazzer.autofuzz.Employee.Builder(\"foo\","
            + " \"bar\").withAge(20).withJobTitle(\"baz\").build()",
        Arrays.asList(
            (byte) 1, // do not return null
            0, // Select the first Builder
            2, // Select two Builder methods returning a builder object (fluent design)
            0, // Select the first build method
            0, // pick the first remaining builder method (withAge)
            0, // pick the first remaining builder method (withJobTitle)
            0, // pick the first build method
            (byte) 1, // do not return null
            6, // remaining bytes
            "foo", // firstName
            (byte) 1, // do not return null
            6, // remaining bytes
            "bar", // lastName
            20, // age
            (byte) 1, // do not return null
            6, // remaining bytes
            "baz" // jobTitle
            ));
  }
}
