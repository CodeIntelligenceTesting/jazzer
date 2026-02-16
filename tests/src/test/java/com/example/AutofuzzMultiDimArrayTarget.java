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

package com.example;

// Regression test for https://github.com/CodeIntelligenceTesting/jazzer/issues/1026.
// It also uses a static inner class array parameter to verify that the reproducer codegen uses
// getCanonicalName() (dot-separated) rather than getName()/getTypeName() (which use '$'
// for inner classes and are not valid Java source).
public class AutofuzzMultiDimArrayTarget {
  public static class Item {
    public Item(int value) {}
  }

  public AutofuzzMultiDimArrayTarget(int[][] grid, Item[] items) {
    if (grid != null && grid.length > 3 && items != null && items.length > 3) {
      throw new RuntimeException();
    }
  }
}
