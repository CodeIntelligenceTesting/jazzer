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
