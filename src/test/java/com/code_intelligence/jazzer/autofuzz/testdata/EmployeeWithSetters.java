/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.autofuzz.testdata;

import java.util.Objects;

public class EmployeeWithSetters {
  private String firstName;
  private String lastName;
  private String jobTitle;
  private int age;

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    EmployeeWithSetters hero = (EmployeeWithSetters) o;
    return age == hero.age
        && Objects.equals(firstName, hero.firstName)
        && Objects.equals(lastName, hero.lastName)
        && Objects.equals(jobTitle, hero.jobTitle);
  }

  @Override
  public int hashCode() {
    return Objects.hash(firstName, lastName, jobTitle, age);
  }

  public void setFirstName(String firstName) {
    this.firstName = firstName;
  }

  public void setLastName(String lastName) {
    this.lastName = lastName;
  }

  public void setJobTitle(String jobTitle) {
    this.jobTitle = jobTitle;
  }

  public void setAge(int age) {
    this.age = age;
  }
}
