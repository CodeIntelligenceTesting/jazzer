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

import java.util.AbstractMap.SimpleEntry;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.function.IntFunction;
import java.util.function.Supplier;
import java.util.stream.Stream;

public final class StreamSupport {
  private StreamSupport() {}

  /**
   * @return the first present value, otherwise {@link Optional#empty()}
   */
  public static <T> Optional<T> findFirstPresent(Stream<Optional<T>> stream) {
    return stream.filter(Optional::isPresent).map(Optional::get).findFirst();
  }

  /**
   * Returns the supplier provided value wrapped in {@link Optional} or, if an exception is thrown,
   * {@code empty}.
   */
  public static <T> Optional<T> suppliedOrEmpty(Supplier<T> supplier) {
    try {
      return Optional.of(supplier.get());
    } catch (Exception e) {
      return Optional.empty();
    }
  }

  /**
   * @return an array with the values if all {@link Optional}s are present, otherwise {@link
   *     Optional#empty()}
   */
  public static <T> Optional<T[]> toArrayOrEmpty(
      Stream<Optional<T>> stream, IntFunction<T[]> newArray) {
    try {
      return Optional.of(stream.map(Optional::get).toArray(newArray));
    } catch (NoSuchElementException e) {
      return Optional.empty();
    }
  }

  /**
   * Return a stream containing the optional value if present, otherwise an empty stream.
   *
   * @return stream containing the optional value
   */
  public static <T> Stream<T> getOrEmpty(Optional<T> optional) {
    return optional.map(Stream::of).orElseGet(Stream::empty);
  }

  public static <K, V> SimpleEntry<K, V> entry(K key, V value) {
    return new SimpleEntry<>(key, value);
  }
}
