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
