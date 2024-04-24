/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.engine;

import com.code_intelligence.jazzer.mutation.api.Cache;
import java.util.IdentityHashMap;
import java.util.Map;

/** {@link Cache} implementation using the key identity. */
@SuppressWarnings("unchecked")
public class IdentityCache implements Cache {

  private final Map<Object, Object> cache = new IdentityHashMap<>();

  @Override
  public <K, V> V get(K key) {
    return (V) cache.get(key);
  }

  @Override
  public <K, V> V put(K key, V value) {
    return (V) cache.put(key, value);
  }

  @Override
  public void clear() {
    cache.clear();
  }
}
