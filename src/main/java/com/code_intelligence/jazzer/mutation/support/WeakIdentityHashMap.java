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

import static java.util.stream.Collectors.toSet;

import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.AbstractMap.SimpleEntry;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * An unoptimized version of a {@link java.util.WeakHashMap} with the semantics of a {@link
 * java.util.IdentityHashMap}.
 *
 * <p>If this class ever becomes a bottleneck, e.g. because of the IdentityWeakReference
 * allocations, it should be replaced by a copy of the * {@link java.util.WeakHashMap} code with all
 * {@code equals} calls dropped and all {@code hashCode} * calls replaced with {@link
 * System#identityHashCode}.
 */
public final class WeakIdentityHashMap<K, V> implements Map<K, V> {
  private final HashMap<WeakReference<K>, V> map = new HashMap<>();
  private final ReferenceQueue<K> weaklyReachables = new ReferenceQueue<>();

  @Override
  public int size() {
    removeNewWeaklyReachables();
    return map.size();
  }

  @Override
  public boolean isEmpty() {
    removeNewWeaklyReachables();
    return map.isEmpty();
  }

  @Override
  public boolean containsKey(Object key) {
    removeNewWeaklyReachables();
    return map.containsKey(new IdentityWeakReference<>(key));
  }

  @Override
  public boolean containsValue(Object value) {
    removeNewWeaklyReachables();
    return map.containsValue(value);
  }

  @Override
  public V get(Object key) {
    removeNewWeaklyReachables();
    return map.get(new IdentityWeakReference<>(key));
  }

  @Override
  public V put(K key, V value) {
    removeNewWeaklyReachables();
    return map.put(new IdentityWeakReference<>(key, weaklyReachables), value);
  }

  @Override
  public V remove(Object key) {
    removeNewWeaklyReachables();
    return map.remove(new IdentityWeakReference<>(key));
  }

  @Override
  public void putAll(Map<? extends K, ? extends V> otherMap) {
    removeNewWeaklyReachables();
    for (Entry<? extends K, ? extends V> entry : otherMap.entrySet()) {
      map.put(new IdentityWeakReference<>(entry.getKey(), weaklyReachables), entry.getValue());
    }
  }

  @Override
  public void clear() {
    map.clear();
  }

  @Override
  public Set<K> keySet() {
    removeNewWeaklyReachables();
    return map.keySet().stream().map(WeakReference::get).filter(Objects::nonNull).collect(toSet());
  }

  @Override
  public Collection<V> values() {
    removeNewWeaklyReachables();
    return map.values();
  }

  @Override
  public Set<Entry<K, V>> entrySet() {
    removeNewWeaklyReachables();
    return map.entrySet().stream()
        .map(e -> new SimpleEntry<>(e.getKey().get(), e.getValue()))
        .filter(e -> e.getKey() != null)
        .collect(toSet());
  }

  void collectKeysForTesting() {
    map.keySet()
        .forEach(
            ref -> {
              ref.clear();
              ref.enqueue();
            });
  }

  private void removeNewWeaklyReachables() {
    Reference<? extends K> referent;
    while ((referent = weaklyReachables.poll()) != null) {
      map.remove(referent);
    }
  }

  private static final class IdentityWeakReference<T> extends WeakReference<T> {
    private final int referentHashCode;

    public IdentityWeakReference(T referent) {
      super(referent);
      this.referentHashCode = System.identityHashCode(referent);
    }

    public IdentityWeakReference(T referent, ReferenceQueue<? super T> queue) {
      super(referent, queue);
      this.referentHashCode = System.identityHashCode(referent);
    }

    @Override
    public boolean equals(Object other) {
      if (this == other) {
        return true;
      }
      if (!(other instanceof WeakReference)) {
        return false;
      }
      T referent = get();
      if (referent == null) {
        return false;
      }
      return referent == ((WeakReference<?>) other).get();
    }

    @Override
    public int hashCode() {
      return referentHashCode;
    }
  }
}
