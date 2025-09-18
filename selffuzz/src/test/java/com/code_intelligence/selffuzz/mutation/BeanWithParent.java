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

public class BeanWithParent extends ConstructorPropertiesAnnotatedBean {
  protected int quz;

  @ConstructorProperties({"foo", "BAR", "baz", "quz"})
  BeanWithParent(boolean a, String b, int c, int q) {
    super(a, b, c);
    this.quz = q;
  }

  public int getQuz() {
    return quz;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    if (!super.equals(o)) return false;
    BeanWithParent that = (BeanWithParent) o;
    return quz == that.quz;
  }

  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), quz);
  }

  @Override
  public String toString() {
    return "BeanWithParent{"
        + "quz="
        + quz
        + ", foo="
        + isFoo()
        + ", bar='"
        + getBAR()
        + '\''
        + ", baz="
        + getBaz()
        + '}';
  }
}
