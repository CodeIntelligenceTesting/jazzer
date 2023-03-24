/*
 * Copyright 2023 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.mutation.mutator.collection;

import static com.code_intelligence.jazzer.mutation.support.Preconditions.check;
import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.parameterTypesIfParameterized;
import static java.lang.Math.min;
import static java.lang.String.format;
import static java.util.stream.Collectors.toMap;

import com.code_intelligence.jazzer.mutation.annotation.WithSize;
import com.code_intelligence.jazzer.mutation.api.*;
import com.code_intelligence.jazzer.mutation.support.StreamSupport;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedType;
import java.util.AbstractMap;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

final class MapMutatorFactory extends MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(AnnotatedType type, MutatorFactory factory) {
    return parameterTypesIfParameterized(type, Map.class)
        .map(parameterTypes
            -> parameterTypes.stream()
                   .map(factory::tryCreate)
                   .flatMap(StreamSupport::getOrEmpty)
                   .collect(Collectors.toList()))
        .map(elementMutators -> {
          check(elementMutators.size() == 2);
          int min = MapMutator.DEFAULT_MIN_SIZE;
          int max = MapMutator.DEFAULT_MAX_SIZE;
          for (Annotation annotation : type.getDeclaredAnnotations()) {
            if (annotation instanceof WithSize) {
              WithSize withSize = (WithSize) annotation;
              min = withSize.min();
              max = withSize.max();
            }
          }
          return new MapMutator<>(elementMutators.get(0), elementMutators.get(1), min, max);
        });
  }

  private static final class MapMutator<K, V> extends SerializingInPlaceMutator<Map<K, V>> {
    private static final int DEFAULT_ATTEMPTS_COUNT = 100;
    private static final int DEFAULT_MIN_SIZE = 0;
    private static final int DEFAULT_MAX_SIZE = 1000;

    private final SerializingMutator<K> keyMutator;
    private final SerializingMutator<V> valueMutator;
    private final int minSize;
    private final int maxSize;

    MapMutator(SerializingMutator<K> keyMutator, SerializingMutator<V> valueMutator, int minSize,
        int maxSize) {
      this.keyMutator = keyMutator;
      this.valueMutator = valueMutator;
      this.minSize = Math.max(minSize, DEFAULT_MIN_SIZE);
      this.maxSize = Math.min(maxSize, DEFAULT_MAX_SIZE);

      require(maxSize >= 1, "WithSize#max needs to be greater than 0");
      require(minSize >= 0, "WithSize#min size needs to be greater or equal 0");
      require(minSize <= maxSize,
          format("WithSize#min %d needs to be smaller or equal than WithSize#max %d", minSize,
              maxSize));
    }

    @Override
    public Map<K, V> read(DataInputStream in) throws IOException {
      int size = Math.min(Math.max(in.readInt(), minSize), maxSize);
      Map<K, V> map = new HashMap<>(size);
      for (int i = 0; i < size; i++) {
        map.put(keyMutator.read(in), valueMutator.read(in));
      }
      // Wrap in an immutable view for additional protection against accidental mutation in fuzz
      // tests.
      return toImmutableMapView(map);
    }

    @Override
    public void write(Map<K, V> map, DataOutputStream out) throws IOException {
      out.writeInt(map.size());
      for (Map.Entry<K, V> entry : map.entrySet()) {
        keyMutator.write(entry.getKey(), out);
        valueMutator.write(entry.getValue(), out);
      }
    }

    @Override
    protected Map<K, V> makeDefaultInstance() {
      // Wrap in an immutable view for additional protection against accidental mutation in fuzz
      // tests.
      return toImmutableMapView(new HashMap<>(maxInitialSize()));
    }

    @Override
    public void initInPlace(Map<K, V> reference, PseudoRandom prng) {
      int targetSize = prng.closedRange(minInitialSize(), maxInitialSize());
      Map<K, V> map = underlyingMutableList(reference);
      map.clear();
      for (int i = 0; i < targetSize; i++) {
        initElement(map, prng);
      }
    }

    @Override
    public void mutateInPlace(Map<K, V> reference, PseudoRandom prng) {
      Map<K, V> map = underlyingMutableList(reference);
      if (map.isEmpty()) {
        initElement(map, prng);
      } else if (!prng.trueInOneOutOf(4)) {
        // Choose a random entry, and then key or value, to mutate.
        int i = prng.indexIn(map.size());
        map.entrySet().stream().skip(i).findFirst().ifPresent(
            entry -> mutateElement(entry, map, prng));
      } else {
        // This will increase the map size up to max and then oscillate around it.
        // Smaller sizes are already used, so increasing the size should be a valid choice.
        // FIXME: Think about a better strategy to change the size.
        int currentSize = map.size();
        if (currentSize < maxSize) {
          // Create a new entry, as a deep copy could be expensive.
          initElement(map, prng);
        } else if (currentSize > minSize) {
          // Remove a random entry.
          int i = prng.indexIn(currentSize);
          map.keySet().stream().skip(i).findFirst().ifPresent(map::remove);
        } else {
          // One element map, mutate that one.
          mutateElement(map.entrySet().iterator().next(), map, prng);
        }
      }
    }

    @Override
    public void crossOverInPlace(Map<K, V> reference, Map<K, V> otherReference, PseudoRandom prng) {

    }

    private void initElement(Map<K, V> map, PseudoRandom prng) {
      // Lookup an unused key first, as the map may already contain and
      // deduplicate it. Keys are solely based on the prng so that an
      // unused one should eventually be found. In case all or most values
      // of the given type are already used, give up after some attempts.
      int attempts = 0;
      K key;
      do {
        if (attempts++ > DEFAULT_ATTEMPTS_COUNT) {
          // Give up, as no unused key could be found.
          return;
        }
        key = keyMutator.init(prng);
      } while (map.containsKey(key));
      map.put(key, valueMutator.init(prng));
    }

    private void mutateElement(Map.Entry<K, V> entry, Map<K, V> map, PseudoRandom prng) {
      K key = entry.getKey();
      V value = entry.getValue();
      boolean mutateKeyOrValue = prng.choice();

      map.remove(key);

      // Try to mutate the current key into an unused one.
      // If that doesn't succeed after some attempts, mutate the value.
      if (mutateKeyOrValue) {
        int attempts = 0;
        K mutated = key;
        while (true) {
          mutated = keyMutator.mutate(mutated, prng);
          if (!mutated.equals(key) && !map.containsKey(mutated)) {
            key = mutated;
            break;
          } else if (attempts++ > DEFAULT_ATTEMPTS_COUNT) {
            // Give up, as no unused key could be found, and mutate the value instead.
            mutateKeyOrValue = false;
            break;
          }
        }
      }

      // The value mutator is responsible to produce different values, no need for a retry.
      if (!mutateKeyOrValue) {
        value = valueMutator.mutate(value, prng);
      }
      map.put(key, value);
    }

    @Override
    public Map<K, V> detach(Map<K, V> value) {
      return value.entrySet().stream().collect(toMap(entry
          -> keyMutator.detach(entry.getKey()),
          entry -> valueMutator.detach(entry.getValue())));
    }

    @Override
    public String toDebugString(Predicate<Debuggable> isInCycle) {
      return "Map<" + keyMutator.toDebugString(isInCycle) + ","
          + valueMutator.toDebugString(isInCycle) + ">";
    }

    private int minInitialSize() {
      return minSize;
    }

    private int maxInitialSize() {
      return min(maxSize, minSize + 1);
    }

    private Map<K, V> underlyingMutableList(Map<K, V> value) {
      if (value instanceof ImmutableMapView<?, ?>) {
        // An immutable map view created by us, so we know how to get back at the mutable list.
        return ((ImmutableMapView<K, V>) value).asMutableMap();
      } else {
        // Any kind of map created by someone else (for example using us as a general purpose
        // InPlaceMutator), so assume it is mutable.
        return value;
      }
    }

    private Map<K, V> toImmutableMapView(Map<K, V> value) {
      if (value instanceof ImmutableMapView) {
        return value;
      } else {
        return new ImmutableMapView<>(value);
      }
    }
  }

  private static final class ImmutableMapView<K, V> extends AbstractMap<K, V> {
    private final Map<K, V> mutableMap;

    ImmutableMapView(Map<K, V> mutableMap) {
      this.mutableMap = mutableMap;
    }

    Map<K, V> asMutableMap() {
      return mutableMap;
    }

    @Override
    public V get(Object i) {
      return mutableMap.get(i);
    }

    @Override
    public Set<Entry<K, V>> entrySet() {
      return Collections.unmodifiableSet(mutableMap.entrySet());
    }

    @Override
    public int size() {
      return mutableMap.size();
    }
  }
}
