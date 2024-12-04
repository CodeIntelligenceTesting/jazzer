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

import com.google.errorprone.annotations.DoNotMock;
import java.util.List;
import java.util.function.Supplier;

@DoNotMock("Use TestSupport#mockPseudoRandom instead")
public interface PseudoRandom {
  /**
   * @return a uniformly random {@code boolean}
   */
  boolean choice();

  /**
   * @return a {@code boolean} that is {@code true} with probability {@code 1/inverseFrequencyTrue}
   */
  boolean trueInOneOutOf(int inverseFrequencyTrue);

  /**
   * @throws IllegalArgumentException if {@code array.length == 0}
   * @return an element from the given array at uniformly random index
   */
  <T> T pickIn(T[] array);

  /**
   * @throws IllegalArgumentException if {@code array.length == 0}
   * @return an element from the given List at uniformly random index
   */
  <T> T pickIn(List<T> array);

  /**
   * @throws IllegalArgumentException if {@code array.length == 0}
   * @return a uniformly random index valid for the given array
   */
  <T> int indexIn(T[] array);

  /**
   * @throws IllegalArgumentException if {@code list.size() == 0}
   * @return a uniformly random index valid for the given list
   */
  <T> int indexIn(List<T> list);

  /**
   * Prefer {@link #indexIn(Object[])} and {@link #indexIn(List)}.
   *
   * @throws IllegalArgumentException if {@code range < 1}
   * @return a uniformly random index in the range {@code [0, range-1]}
   */
  int indexIn(int range);

  /**
   * @throws IllegalArgumentException if {@code array.length < 2}
   * @return a uniformly random index valid for the given array and different from {@code
   *     currentIndex}
   */
  <T> int otherIndexIn(T[] array, int currentIndex);

  /**
   * @throws IllegalArgumentException if {@code length < 2}
   * @return a uniformly random {@code int} in the closed range {@code [0, length)} that is
   *     different from {@code currentIndex}
   */
  int otherIndexIn(int range, int currentIndex);

  /**
   * @return a uniformly random {@code int} in the closed range {@code [lowerInclusive,
   *     upperInclusive]}.
   */
  int closedRange(int lowerInclusive, int upperInclusive);

  /**
   * @return a uniformly random {@code long} in the closed range {@code [lowerInclusive,
   *     upperInclusive]}.
   */
  long closedRange(long lowerInclusive, long upperInclusive);

  /**
   * @return a uniformly random {@code float} in the closed range {@code [lowerInclusive,
   *     upperInclusive]}.
   */
  float closedRange(float lowerInclusive, float upperInclusive);

  /**
   * @return a uniformly random {@code double} in the closed range {@code [lowerInclusive,
   *     upperInclusive]}.
   */
  double closedRange(double lowerInclusive, double upperInclusive);

  /**
   * Returns random value in the closed range [lowerInclusive, upperInclusive], meant to be used as
   * the size of a collection or subset thereof.
   *
   * @param elementsHaveFixedSize Whether the elements of the collection have a fixed size
   *     representation.
   */
  int sizeInClosedRange(int lowerInclusive, int upperInclusive, boolean elementsHaveFixedSize);

  /** Fills the given array with random bytes. */
  void bytes(byte[] bytes);

  /**
   * Use the given supplier to produce a value with probability {@code 1/inverseSupplierFrequency},
   * otherwise randomly return one of the given values.
   *
   * @return value produced by the supplier or one of the given values
   */
  <T> T pickValue(T value, T otherValue, Supplier<T> supplier, int inverseSupplierFrequency);

  /**
   * Returns a pseudorandom {@code long} value.
   *
   * @return a pseudorandom {@code long} value
   */
  long nextLong();
}
