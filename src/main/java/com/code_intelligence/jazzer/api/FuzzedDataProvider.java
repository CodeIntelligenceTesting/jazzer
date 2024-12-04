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

package com.code_intelligence.jazzer.api;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Random;

/**
 * A convenience wrapper turning the raw fuzzer input bytes into Java primitive types.
 *
 * <p>The methods defined by this interface behave similarly to {@link Random#nextInt()}, with all
 * returned values depending deterministically on the fuzzer input for the current run.
 */
public interface FuzzedDataProvider {
  /**
   * Consumes a {@code boolean} from the fuzzer input.
   *
   * @return a {@code boolean}
   */
  boolean consumeBoolean();

  /**
   * Consumes a {@code boolean} array from the fuzzer input.
   *
   * <p>The array will usually have length {@code length}, but might be shorter if the fuzzer input
   * is not sufficiently long.
   *
   * @param maxLength the maximum length of the array
   * @return a {@code boolean} array of length at most {@code length}
   */
  boolean[] consumeBooleans(int maxLength);

  /**
   * Consumes a {@code byte} from the fuzzer input.
   *
   * @return a {@code byte}
   */
  byte consumeByte();

  /**
   * Consumes a {@code byte} between {@code min} and {@code max} from the fuzzer input.
   *
   * @param min the inclusive lower bound on the returned value
   * @param max the inclusive upper bound on the returned value
   * @return a {@code byte} in the range {@code [min, max]}
   */
  byte consumeByte(byte min, byte max);

  /**
   * Consumes a {@code byte} array from the fuzzer input.
   *
   * <p>The array will usually have length {@code length}, but might be shorter if the fuzzer input
   * is not sufficiently long.
   *
   * @param maxLength the maximum length of the array
   * @return a {@code byte} array of length at most {@code length}
   */
  byte[] consumeBytes(int maxLength);

  /**
   * Consumes the remaining fuzzer input as a {@code byte} array.
   *
   * <p><b>Note:</b> After calling this method, further calls to methods of this interface will
   * return fixed values only.
   *
   * @return a {@code byte} array
   */
  byte[] consumeRemainingAsBytes();

  /**
   * Consumes a {@code short} from the fuzzer input.
   *
   * @return a {@code short}
   */
  short consumeShort();

  /**
   * Consumes a {@code short} between {@code min} and {@code max} from the fuzzer input.
   *
   * @param min the inclusive lower bound on the returned value
   * @param max the inclusive upper bound on the returned value
   * @return a {@code short} in the range {@code [min, max]}
   */
  short consumeShort(short min, short max);

  /**
   * Consumes a {@code short} array from the fuzzer input.
   *
   * <p>The array will usually have length {@code length}, but might be shorter if the fuzzer input
   * is not sufficiently long.
   *
   * @param maxLength the maximum length of the array
   * @return a {@code short} array of length at most {@code length}
   */
  short[] consumeShorts(int maxLength);

  /**
   * Consumes an {@code int} from the fuzzer input.
   *
   * @return an {@code int}
   */
  int consumeInt();

  /**
   * Consumes an {@code int} between {@code min} and {@code max} from the fuzzer input.
   *
   * @param min the inclusive lower bound on the returned value
   * @param max the inclusive upper bound on the returned value
   * @return an {@code int} in the range {@code [min, max]}
   */
  int consumeInt(int min, int max);

  /**
   * Consumes an {@code int} array from the fuzzer input.
   *
   * <p>The array will usually have length {@code length}, but might be shorter if the fuzzer input
   * is not sufficiently long.
   *
   * @param maxLength the maximum length of the array
   * @return an {@code int} array of length at most {@code length}
   */
  int[] consumeInts(int maxLength);

  /**
   * Consumes a {@code long} from the fuzzer input.
   *
   * @return a {@code long}
   */
  long consumeLong();

  /**
   * Consumes a {@code long} between {@code min} and {@code max} from the fuzzer input.
   *
   * @param min the inclusive lower bound on the returned value
   * @param max the inclusive upper bound on the returned value
   * @return a {@code long} in the range @{code [min, max]}
   */
  long consumeLong(long min, long max);

  /**
   * Consumes a {@code long} array from the fuzzer input.
   *
   * <p>The array will usually have length {@code length}, but might be shorter if the fuzzer input
   * is not sufficiently long.
   *
   * @param maxLength the maximum length of the array
   * @return a {@code long} array of length at most {@code length}
   */
  long[] consumeLongs(int maxLength);

  /**
   * Consumes a {@code float} from the fuzzer input.
   *
   * @return a {@code float} that may have a special value (e.g. a NaN or infinity)
   */
  float consumeFloat();

  /**
   * Consumes a regular {@code float} from the fuzzer input.
   *
   * @return a {@code float} that is not a special value (e.g. not a NaN or infinity)
   */
  float consumeRegularFloat();

  /**
   * Consumes a regular {@code float} between {@code min} and {@code max} from the fuzzer input.
   *
   * @return a {@code float} in the range {@code [min, max]}
   */
  float consumeRegularFloat(float min, float max);

  /**
   * Consumes a {@code float} between 0.0 and 1.0 (inclusive) from the fuzzer input.
   *
   * @return a {@code float} in the range {@code [0.0, 1.0]}
   */
  float consumeProbabilityFloat();

  /**
   * Consumes a {@code double} from the fuzzer input.
   *
   * @return a {@code double} that may have a special value (e.g. a NaN or infinity)
   */
  double consumeDouble();

  /**
   * Consumes a regular {@code double} from the fuzzer input.
   *
   * @return a {@code double} that is not a special value (e.g. not a NaN or infinity)
   */
  double consumeRegularDouble();

  /**
   * Consumes a regular {@code double} between {@code min} and {@code max} from the fuzzer input.
   *
   * @return a {@code double} in the range {@code [min, max]}
   */
  double consumeRegularDouble(double min, double max);

  /**
   * Consumes a {@code double} between 0.0 and 1.0 (inclusive) from the fuzzer input.
   *
   * @return a {@code double} in the range {@code [0.0, 1.0]}
   */
  double consumeProbabilityDouble();

  /** Consumes a {@code char} from the fuzzer input. */
  char consumeChar();

  /**
   * Consumes a {@code char} between {@code min} and {@code max} from the fuzzer input.
   *
   * @param min the inclusive lower bound on the returned value
   * @param max the inclusive upper bound on the returned value
   * @return a {@code char} in the range {@code [min, max]}
   */
  char consumeChar(char min, char max);

  /** Consumes a {@code char} from the fuzzer input that is never a UTF-16 surrogate character. */
  char consumeCharNoSurrogates();

  /**
   * Consumes a {@link String} from the fuzzer input.
   *
   * <p>The returned string may be of any length between 0 and {@code maxLength}, even if there is
   * more fuzzer input available.
   *
   * @param maxLength the maximum length of the string
   * @return a {@link String} of length between 0 and {@code maxLength} (inclusive)
   */
  String consumeString(int maxLength);

  /**
   * Consumes the remaining fuzzer input as a {@link String}.
   *
   * <p><b>Note:</b> After calling this method, further calls to methods of this interface will
   * return fixed values only.
   *
   * @return a {@link String}
   */
  String consumeRemainingAsString();

  /**
   * Consumes an ASCII-only {@link String} from the fuzzer input.
   *
   * <p>The returned string may be of any length between 0 and {@code maxLength}, even if there is
   * more fuzzer input available.
   *
   * @param maxLength the maximum length of the string
   * @return a {@link String} of length between 0 and {@code maxLength} (inclusive) that contains
   *     only ASCII characters
   */
  String consumeAsciiString(int maxLength);

  /**
   * Consumes the remaining fuzzer input as an ASCII-only {@link String}.
   *
   * <p><b>Note:</b> After calling this method, further calls to methods of this interface will
   * return fixed values only.
   *
   * @return a {@link String} that contains only ASCII characters
   */
  String consumeRemainingAsAsciiString();

  /**
   * Returns the number of unconsumed bytes in the fuzzer input.
   *
   * @return the number of unconsumed bytes in the fuzzer input
   */
  int remainingBytes();

  /**
   * Picks an element from {@code collection} based on the fuzzer input.
   *
   * <p><b>Note:</b> The distribution of picks is not perfectly uniform.
   *
   * @param collection the {@link Collection} to pick an element from.
   * @param <T> the type of the collection element
   * @return an element from {@code collection} chosen based on the fuzzer input
   */
  @SuppressWarnings("unchecked")
  default <T> T pickValue(Collection<T> collection) {
    int size = collection.size();
    if (size == 0) {
      throw new IllegalArgumentException("collection is empty");
    }
    if (collection instanceof List<?>) {
      return ((List<T>) collection).get(consumeInt(0, size - 1));
    } else {
      return (T) pickValue(collection.toArray());
    }
  }

  /**
   * Picks an element from {@code array} based on the fuzzer input.
   *
   * <p><b>Note:</b> The distribution of picks is not perfectly uniform.
   *
   * @param array the array to pick an element from.
   * @param <T> the type of the array element
   * @return an element from {@code array} chosen based on the fuzzer input
   */
  default <T> T pickValue(T[] array) {
    if (array.length == 0) {
      throw new IllegalArgumentException("array is empty");
    }
    return array[consumeInt(0, array.length - 1)];
  }

  /**
   * Picks an element from {@code array} based on the fuzzer input.
   *
   * <p><b>Note:</b> The distribution of picks is not perfectly uniform.
   *
   * @param array the array to pick an element from.
   * @return an element from {@code array} chosen based on the fuzzer input
   */
  default boolean pickValue(boolean[] array) {
    if (array.length == 0) {
      throw new IllegalArgumentException("array is empty");
    }
    return array[consumeInt(0, array.length - 1)];
  }

  /**
   * Picks an element from {@code array} based on the fuzzer input.
   *
   * <p><b>Note:</b> The distribution of picks is not perfectly uniform.
   *
   * @param array the array to pick an element from.
   * @return an element from {@code array} chosen based on the fuzzer input
   */
  default byte pickValue(byte[] array) {
    if (array.length == 0) {
      throw new IllegalArgumentException("array is empty");
    }
    return array[consumeInt(0, array.length - 1)];
  }

  /**
   * Picks an element from {@code array} based on the fuzzer input.
   *
   * <p><b>Note:</b> The distribution of picks is not perfectly uniform.
   *
   * @param array the array to pick an element from.
   * @return an element from {@code array} chosen based on the fuzzer input
   */
  default short pickValue(short[] array) {
    if (array.length == 0) {
      throw new IllegalArgumentException("array is empty");
    }
    return array[consumeInt(0, array.length - 1)];
  }

  /**
   * Picks an element from {@code array} based on the fuzzer input.
   *
   * <p><b>Note:</b> The distribution of picks is not perfectly uniform.
   *
   * @param array the array to pick an element from.
   * @return an element from {@code array} chosen based on the fuzzer input
   */
  default int pickValue(int[] array) {
    if (array.length == 0) {
      throw new IllegalArgumentException("array is empty");
    }
    return array[consumeInt(0, array.length - 1)];
  }

  /**
   * Picks an element from {@code array} based on the fuzzer input.
   *
   * <p><b>Note:</b> The distribution of picks is not perfectly uniform.
   *
   * @param array the array to pick an element from.
   * @return an element from {@code array} chosen based on the fuzzer input
   */
  default long pickValue(long[] array) {
    if (array.length == 0) {
      throw new IllegalArgumentException("array is empty");
    }
    return array[consumeInt(0, array.length - 1)];
  }

  /**
   * Picks an element from {@code array} based on the fuzzer input.
   *
   * <p><b>Note:</b> The distribution of picks is not perfectly uniform.
   *
   * @param array the array to pick an element from.
   * @return an element from {@code array} chosen based on the fuzzer input
   */
  default double pickValue(double[] array) {
    if (array.length == 0) {
      throw new IllegalArgumentException("array is empty");
    }
    return array[consumeInt(0, array.length - 1)];
  }

  /**
   * Picks an element from {@code array} based on the fuzzer input.
   *
   * <p><b>Note:</b> The distribution of picks is not perfectly uniform.
   *
   * @param array the array to pick an element from.
   * @return an element from {@code array} chosen based on the fuzzer input
   */
  default float pickValue(float[] array) {
    if (array.length == 0) {
      throw new IllegalArgumentException("array is empty");
    }
    return array[consumeInt(0, array.length - 1)];
  }

  /**
   * Picks an element from {@code array} based on the fuzzer input.
   *
   * <p><b>Note:</b> The distribution of picks is not perfectly uniform.
   *
   * @param array the array to pick an element from.
   * @return an element from {@code array} chosen based on the fuzzer input
   */
  default char pickValue(char[] array) {
    if (array.length == 0) {
      throw new IllegalArgumentException("array is empty");
    }
    return array[consumeInt(0, array.length - 1)];
  }

  /**
   * Picks {@code numOfElements} elements from {@code collection} based on the fuzzer input.
   *
   * <p><b>Note:</b> The distribution of picks is not perfectly uniform.
   *
   * @param collection the {@link Collection} to pick an element from.
   * @param numOfElements the number of elements to pick.
   * @param <T> the type of the collection element
   * @return an array of size {@code numOfElements} from {@code collection} chosen based on the
   *     fuzzer input
   */
  default <T> List<T> pickValues(Collection<T> collection, int numOfElements) {
    int size = collection.size();
    if (size == 0) {
      throw new IllegalArgumentException("collection is empty");
    }
    if (numOfElements > collection.size()) {
      throw new IllegalArgumentException("numOfElements exceeds collection.size()");
    }

    List<T> remainingElements = new ArrayList<>(collection);
    List<T> pickedElements = new ArrayList<>();
    for (int i = 0; i < numOfElements; i++) {
      T element = pickValue(remainingElements);
      pickedElements.add(element);
      remainingElements.remove(element);
    }
    return pickedElements;
  }

  /**
   * Picks {@code numOfElements} elements from {@code array} based on the fuzzer input.
   *
   * <p><b>Note:</b> The distribution of picks is not perfectly uniform.
   *
   * @param array the array to pick an element from.
   * @param numOfElements the number of elements to pick.
   * @param <T> the type of the array element
   * @return an array of size {@code numOfElements} from {@code array} chosen based on the fuzzer
   *     input
   */
  default <T> List<T> pickValues(T[] array, int numOfElements) {
    if (array.length == 0) {
      throw new IllegalArgumentException("array is empty");
    }
    return pickValues(Arrays.asList(array), numOfElements);
  }
}
