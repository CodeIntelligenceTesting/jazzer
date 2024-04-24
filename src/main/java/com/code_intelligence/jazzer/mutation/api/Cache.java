/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.api;

/**
 * A cache that can be used during _one_ fizzing iteration to save generated objects. <br>
 * Generally, mutators should try to stay stateless and only rely on the cache as a last resort.
 */
public interface Cache {

  <K, V> V get(K key);

  <K, V> V put(K key, V value);

  void clear();
}
