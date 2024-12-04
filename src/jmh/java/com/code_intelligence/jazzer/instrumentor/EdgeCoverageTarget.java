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

package com.code_intelligence.jazzer.instrumentor;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

public class EdgeCoverageTarget {
  private final Random rnd = new Random();

  @SuppressWarnings("unused")
  public List<Integer> exampleMethod() {
    ArrayList<Integer> rnds = new ArrayList<>();
    rnds.add(rnd.nextInt());
    rnds.add(rnd.nextInt());
    rnds.add(rnd.nextInt());
    rnds.add(rnd.nextInt());
    rnds.add(rnd.nextInt());
    int i = rnd.nextInt() + rnd.nextInt();
    if (i > 0 && i < Integer.MAX_VALUE / 2) {
      i--;
    } else {
      i++;
    }
    rnds.add(i);
    return rnds.stream().map(n -> n + 1).collect(Collectors.toList());
  }
}
