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
import com.code_intelligence.jazzer.mutation.support.RandomSupport;
import com.code_intelligence.jazzer.mutation.support.StreamSupport;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedType;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
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
      int size = RandomSupport.clamp(in.readInt(), minSize, maxSize);
      Map<K, V> map = new LinkedHashMap<>(size);
      for (int i = 0; i < size; i++) {
        map.put(keyMutator.read(in), valueMutator.read(in));
      }
      // Wrap in an immutable view for additional protection against accidental
      // mutation in fuzz
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
      // Wrap in an immutable view for additional protection against accidental
      // mutation in fuzz
      // tests.
      return toImmutableMapView(new LinkedHashMap<>(maxInitialSize()));
    }

    @Override
    public void initInPlace(Map<K, V> reference, PseudoRandom prng) {
      int targetSize = prng.closedRange(minInitialSize(), maxInitialSize());
      Map<K, V> map = underlyingMutableMap(reference);
      map.clear();
      for (int i = 0; i < targetSize; i++) {
        initElement(map, prng);
      }
    }

    private void eraseRandomChunk(Map<K, V> map, PseudoRandom prng) {
      int mapSize = map.size();
      int upperLimit = Math.max(1, Math.min(mapSize - minSize, mapSize / 2));
      int chunkSize = upperLimit == 1 ? 1 : prng.closedRange(1, upperLimit);
      int chunkOffset = prng.closedRange(0, mapSize - chunkSize);

      List<K> tmpRemStore = map.entrySet()
                                .stream()
                                .skip(chunkOffset)
                                .limit(chunkSize)
                                .map(Map.Entry::getKey)
                                .collect(Collectors.toCollection(() -> new ArrayList<>(chunkSize)));

      map.keySet().removeAll(tmpRemStore);
    }

    private void insertRandomChunk(Map<K, V> map, PseudoRandom prng) {
      int mapSize = map.size();
      int chunkSize = prng.closedRange(1, Math.min(maxSize - mapSize, mapSize));
      for (int i = 0; i < chunkSize; i++) {
        initElement(map, prng);
      }
    }

    private void changeRandomChunk(Map<K, V> map, PseudoRandom prng) {
      int mapSize = map.size();
      int chunkOffset = prng.indexIn(mapSize);
      int chunkSize =
          Math.min(prng.closedRange(1, mapSize - chunkOffset), (int) Math.ceil(mapSize / 10.0));
      List<K> keys =
          map.keySet().stream().skip(chunkOffset).limit(chunkSize).collect(Collectors.toList());

      for (int i = 0; i < keys.size(); i++) {
        K key = keys.get(i);
        V value = map.get(key);
        Map.Entry<K, V> entry = new AbstractMap.SimpleEntry<>(key, value);
        mutateElement(entry, map, prng);
      }
    }

    private static enum Action {
      SHRINK,
      SHRINK_CHUNK,
      GROW,
      GROW_CHUNK,
      CHANGE,
      CHANGE_CHUNK,
    }

    @Override
    public void mutateInPlace(Map<K, V> reference, PseudoRandom prng) {
      Map<K, V> map = underlyingMutableMap(reference);
      if (map.isEmpty()) {
        initElement(map, prng);
        return;
      }
      int currentMapSize = map.size();
      if (currentMapSize == 1) {
        // One element map, mutate that one and return quicker
        map.entrySet().stream().findFirst().ifPresent(entry -> mutateElement(entry, map, prng));
        return;
      }
      List<Action> s = new ArrayList<>();
      if (currentMapSize > minSize) {
        s.add(Action.SHRINK);
        s.add(Action.SHRINK_CHUNK);
      }
      if (currentMapSize < maxSize) {
        s.add(Action.GROW);
        s.add(Action.GROW_CHUNK);
      }
      if (!map.isEmpty()) {
        s.add(Action.CHANGE);
        s.add(Action.CHANGE_CHUNK);
      }
      switch (s.get(prng.indexIn(s))) {
        case SHRINK:
          map.keySet()
              .stream()
              .skip(prng.indexIn(currentMapSize))
              .findFirst()
              .ifPresent(entry -> map.remove(entry));
          return;
        case SHRINK_CHUNK:
          eraseRandomChunk(map, prng);
          return;
        case GROW:
          initElement(map, prng);
          return;
        case GROW_CHUNK:
          insertRandomChunk(map, prng);
          return;
        case CHANGE:
          map.entrySet()
              .stream()
              .skip(prng.indexIn(currentMapSize))
              .findFirst()
              .ifPresent(entry -> mutateElement(entry, map, prng));
          return;
        case CHANGE_CHUNK:
          changeRandomChunk(map, prng);
          return;
      }
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
      boolean mutateKeyOrValue = prng.choice();
      if (mutateKeyOrValue) {
        // Try to mutate the key.
        K originalKey = entry.getKey();

        // Try to mutate the current key into an unused one.
        // If that doesn't succeed after some attempts, mutate the value.
        K mutated = originalKey;
        for (int attempt = 0; attempt < DEFAULT_ATTEMPTS_COUNT; attempt++) {
          mutated = keyMutator.mutate(mutated, prng);
          if (!map.containsKey(mutated)) {
            map.put(mutated, entry.getValue());
            map.remove(originalKey);
            return;
          }
        }
      }

      // Mutate the value.
      if (!mutateKeyOrValue) {
        V value = entry.getValue();
        K key = entry.getKey();
        value = valueMutator.mutate(value, prng);
        map.put(key, value);
      } else {
        entry.setValue(valueMutator.mutate(entry.getValue(), prng));
      }
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

    private Map<K, V> underlyingMutableMap(Map<K, V> value) {
      if (value instanceof ImmutableMapView<?, ?>) {
        // An immutable map view created by us, so we know how to get back at the
        // mutable list.
        return ((ImmutableMapView<K, V>) value).asMutableMap();
      } else {
        // Any kind of map created by someone else (for example using us as a general
        // purpose
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
