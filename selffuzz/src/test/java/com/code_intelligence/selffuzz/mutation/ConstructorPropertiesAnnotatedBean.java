/*
 * Copyright 2025 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.code_intelligence.selffuzz.mutation;

import java.beans.ConstructorProperties;
import java.util.Objects;

public class ConstructorPropertiesAnnotatedBean {
  private final boolean foo;
  private final String bar;
  private final int baz;

  @ConstructorProperties({"foo", "BAR", "baz"})
  ConstructorPropertiesAnnotatedBean(boolean a, String b, int c) {
    this.foo = a;
    this.bar = b;
    this.baz = c;
  }

  public boolean isFoo() {
    return foo;
  }

  public String getBAR() {
    return bar;
  }

  int getBaz() {
    return baz;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    ConstructorPropertiesAnnotatedBean that = (ConstructorPropertiesAnnotatedBean) o;
    return foo == that.foo && baz == that.baz && Objects.equals(bar, that.bar);
  }

  @Override
  public int hashCode() {
    return Objects.hash(foo, bar, baz);
  }

  @Override
  public String toString() {
    return "SimpleTypeBean{" + "foo=" + foo + ", bar='" + bar + '\'' + ", baz=" + baz + '}';
  }
}
