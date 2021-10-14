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
import java.util.Arrays;
import java.util.Objects;
import org.junit.Test;

interface InterfaceA {
  void foo();

  void bar();
}

abstract class ClassA1 implements InterfaceA {
  @Override
  public void foo() {}
}

class ClassB1 extends ClassA1 {
  int n;

  public ClassB1(int _n) {
    n = _n;
  }

  @Override
  public void bar() {}

  @Override
  public boolean equals(Object o) {
    if (this == o)
      return true;
    if (o == null || getClass() != o.getClass())
      return false;
    ClassB1 classB1 = (ClassB1) o;
    return n == classB1.n;
  }

  @Override
  public int hashCode() {
    return Objects.hash(n);
  }
}

class ClassB2 implements InterfaceA {
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
    if (this == o)
      return true;
    if (o == null || getClass() != o.getClass())
      return false;
    ClassB2 classB2 = (ClassB2) o;
    return Objects.equals(s, classB2.s);
  }

  @Override
  public int hashCode() {
    return Objects.hash(s);
  }
}

public class InterfaceCreationTest {
  FuzzedDataProvider data = CannedFuzzedDataProvider.create(Arrays.asList(0, // pick ClassB1
      0, // pick first constructor
      5, // arg for ClassB1 constructor
      1, // pick ClassB2
      0, // pick first constructor
      8, // remaining bytes
      "test" // arg for ClassB2 constructor
      ));

  @Test
  public void testConsumeInterface() {
    assertEquals(Meta.consume(data, InterfaceA.class), new ClassB1(5));
    assertEquals(Meta.consume(data, InterfaceA.class), new ClassB2("test"));
  }
}
