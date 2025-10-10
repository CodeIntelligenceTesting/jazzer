/*
 * Copyright 2025 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.code_intelligence.jazzer.mutation.combinator;

import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static java.util.Objects.requireNonNull;

import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public final class SamplingUtils {

  public static <T> Function<PseudoRandom, T> weightedSampler(T[] values, double[] weights) {
    // Use Vose's alias method for O(1) sampling after O(n) preprocessing.
    requireNonNull(values, "Values must not be null");
    requireNonNull(weights, "Weights must not be null");
    require(values.length > 0, "Values must not be empty");
    require(values.length == weights.length, "Values and weights must have the same length");

    double sum = Arrays.stream(weights).sum();
    require(sum > 0, "At least one weight must be positive");

    int n = values.length;
    int[] alias = new int[n];
    double[] probability = new double[n];
    double[] scaledWeights = Arrays.stream(weights).map(w -> w * n / sum).toArray();
    int[] small = new int[n];
    int[] large = new int[n];
    int smallCount = 0;
    int largeCount = 0;
    for (int i = 0; i < n; i++) {
      if (scaledWeights[i] < 1.0) {
        small[smallCount++] = i;
      } else {
        large[largeCount++] = i;
      }
    }

    while (smallCount > 0 && largeCount > 0) {
      int less = small[--smallCount];
      int more = large[--largeCount];

      probability[less] = scaledWeights[less];
      alias[less] = more;
      scaledWeights[more] = (scaledWeights[more] + scaledWeights[less]) - 1.0;

      if (scaledWeights[more] < 1.0) {
        small[smallCount++] = more;
      } else {
        large[largeCount++] = more;
      }
    }
    while (largeCount > 0) {
      probability[large[--largeCount]] = 1.0;
    }

    while (smallCount > 0) {
      probability[small[--smallCount]] = 1.0;
    }
    return (PseudoRandom random) -> {
      int column = random.indexIn(n);
      return values[random.closedRange(0.0, 1.0) < probability[column] ? column : alias[column]];
    };
  }

  public static <T> Function<PseudoRandom, T> weightedSampler(
      List<WeightedMutationFunction<T>> weightedFunctions) {
    requireNonNull(weightedFunctions, "Weighted functions must not be null");
    require(!weightedFunctions.isEmpty(), "Weighted functions must not be empty");

    double[] weights = weightedFunctions.stream().mapToDouble(m -> m.weight).toArray();

    T[] fns = (T[]) weightedFunctions.stream().map(m -> m.fn).toArray(Object[]::new);

    return weightedSampler(fns, weights);
  }

  @SafeVarargs
  public static <T> Function<PseudoRandom, T> weightedSampler(
      Optional<WeightedMutationFunction<T>>... values) {
    return weightedSampler(
        Arrays.stream(values)
            .filter(Optional::isPresent)
            .map(Optional::get)
            .collect(Collectors.toList()));
  }

  /**
   * A simple struct to hold a mutation function and its weight. It is here just for stylistic
   * reasons, to make the definitions of weights and functions more readable.
   */
  public static class WeightedMutationFunction<T> {
    public final double weight;
    public final T fn;

    public WeightedMutationFunction(double weight, T fn) {
      this.fn = fn;
      this.weight = weight;
    }

    public static <T> WeightedMutationFunction<T> of(double weight, T fn) {
      return new WeightedMutationFunction<>(weight, fn);
    }

    public static <T> Optional<WeightedMutationFunction<T>> ofOptional(double weight, T fn) {
      return Optional.of(new WeightedMutationFunction<>(weight, fn));
    }
  }
}
