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

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.WithSize;
import java.util.List;

public final class ListOfIntegersFuzzer {
  public static void fuzzerTestOneInput(
      @NotNull @WithSize(min = 10, max = 10) List<@NotNull Integer> data) {
    if (data.size() != 10) return;

    if (data.get(0) == 10) {
      if (data.get(1) == 200000) {
        if (data.get(2) == 300000) {
          if (data.get(3) == 102031) {
            if (data.get(4) == 918736) {
              if (data.get(5) == 12301) {
                throw new TreasureFoundException();
              }
            }
          }
        }
      }
    }
  }

  private static class TreasureFoundException extends RuntimeException {}
}
