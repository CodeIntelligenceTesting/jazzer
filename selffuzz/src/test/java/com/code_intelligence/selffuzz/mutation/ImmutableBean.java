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

import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class ImmutableBean {
  private final int i;
  private final boolean b;
  private final List<String> list;

  public ImmutableBean() {
    this(0, false, Collections.emptyList());
  }

  private ImmutableBean(int i, boolean b, List<String> list) {
    this.i = i;
    this.b = b;
    this.list = list;
  }

  public int getI() {
    return i;
  }

  public boolean isB() {
    return b;
  }

  public ImmutableBean withI(int i) {
    return new ImmutableBean(i, b, list);
  }

  // Both withX and setX are supported on immutable builders.
  public ImmutableBean setB(boolean b) {
    return new ImmutableBean(i, b, list);
  }

  public ImmutableBean setList(List<String> list) {
    return new ImmutableBean(i, b, list);
  }

  public List<String> getList() {
    return list;
  }

  @Override
  @SuppressWarnings("PatternVariableCanBeUsed")
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof ImmutableBean)) return false;
    ImmutableBean that = (ImmutableBean) o;
    return i == that.i && b == that.b;
  }

  @Override
  public int hashCode() {
    return Objects.hash(i, b);
  }

  @Override
  public String toString() {
    return "ImmutableBuilder{" + "i=" + i + ", b=" + b + '}';
  }
}
