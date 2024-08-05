/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
