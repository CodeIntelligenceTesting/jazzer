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

import com.code_intelligence.jazzer.autofuzz.testdata.EmployeeWithSetters;
import java.util.Arrays;
import org.junit.Test;

public class SettersTest {
  @Test
  public void testEmptyConstructorWithSetters() {
    EmployeeWithSetters employee = new EmployeeWithSetters();
    employee.setFirstName("foo");
    employee.setAge(26);

    consumeTestCase(
        employee,
        "((java.util.function.Supplier<com.code_intelligence.jazzer.autofuzz.testdata.EmployeeWithSetters>)"
            + " (() -> {com.code_intelligence.jazzer.autofuzz.testdata.EmployeeWithSetters"
            + " autofuzzVariable0 = new"
            + " com.code_intelligence.jazzer.autofuzz.testdata.EmployeeWithSetters();"
            + " autofuzzVariable0.setFirstName(\"foo\"); autofuzzVariable0.setAge(26); return"
            + " autofuzzVariable0;})).get()",
        Arrays.asList(
            (byte) 1, // do not return null for EmployeeWithSetters
            0, // pick first constructor
            2, // pick two setters
            1, // pick second setter
            0, // pick first setter
            (byte) 1, // do not return null for String
            6, // remaining bytes
            "foo", // setFirstName
            26 // setAge
            ));
  }
}
