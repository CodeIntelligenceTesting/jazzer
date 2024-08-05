/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.support;

import static com.google.common.truth.Truth.assertThat;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

class WeakIdentityHashMapTest {
  private static void reachabilityFence(Object o) {
    // Polyfill for JDK 9+ Reference.reachabilityFence:
    // https://mail.openjdk.org/pipermail/core-libs-dev/2018-February/051312.html
  }

  @Test
  void testWeakIdentityHashMap_hasIdentitySemantics() {
    WeakIdentityHashMap<List<Integer>, String> map = new WeakIdentityHashMap<>();

    List<Integer> list = Arrays.asList(1, 2);
    map.put(list, "value");
    assertThat(map.containsKey(list)).isTrue();

    List<Integer> equalList = Arrays.asList(1, 2);
    assertThat(map.containsKey(equalList)).isFalse();

    reachabilityFence(list);
  }

  @Test
  void testWeakIdentityHashMap_hasWeakSemantics() {
    WeakIdentityHashMap<List<Integer>, String> map = new WeakIdentityHashMap<>();

    List<Integer> list = Arrays.asList(1, 2);
    map.put(list, "value");
    assertThat(map.containsKey(list)).isTrue();
    assertThat(map.size()).isEqualTo(1);
    assertThat(map.isEmpty()).isFalse();

    reachabilityFence(list);
    map.collectKeysForTesting();

    assertThat(map.size()).isEqualTo(0);
    assertThat(map.isEmpty()).isTrue();
  }
}
