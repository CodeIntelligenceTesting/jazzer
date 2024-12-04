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
