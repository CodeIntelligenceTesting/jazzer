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
