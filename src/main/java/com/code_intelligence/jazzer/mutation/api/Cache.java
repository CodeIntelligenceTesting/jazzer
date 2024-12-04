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
