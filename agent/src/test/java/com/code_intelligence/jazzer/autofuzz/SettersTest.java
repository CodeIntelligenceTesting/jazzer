// Copyright 2021 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.code_intelligence.jazzer.autofuzz;

import static org.junit.Assert.assertEquals;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.autofuzz.testdata.EmployeeWithSetters;
import java.util.Arrays;
import org.junit.Test;

public class SettersTest {
  FuzzedDataProvider data =
      CannedFuzzedDataProvider.create(Arrays.asList(0, // pick first constructor
          2, // pick two setters
          1, // pick second setter
          0, // pick first setter
          6, // remaining bytes
          "foo", // setFirstName
          26 // setAge
          ));

  @Test
  public void testEmptyConstructorWithSetters() {
    EmployeeWithSetters employee = new EmployeeWithSetters();
    employee.setFirstName("foo");
    employee.setAge(26);
    assertEquals(Meta.consume(data, EmployeeWithSetters.class), employee);
  }
}
