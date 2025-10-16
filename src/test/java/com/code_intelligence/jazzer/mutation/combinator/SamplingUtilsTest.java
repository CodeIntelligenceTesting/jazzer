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

import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.engine.SeededPseudoRandom;
import java.util.function.Function;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class SamplingUtilsTest {
  static Stream<?> weightsProvider() {
    final int N = 1000000;
    final double T = 0.03;
    return Stream.of(
        arguments(N, T, new double[] {1.0, 1.0, 1.0}),
        arguments(N, T, new double[] {1.0, 2.0, 3.0, 4.0, 5.0}),
        arguments(N, T, new double[] {0.1, 0.2, 0.3, 0.4}),
        arguments(N, T, new double[] {10.0, 0.0, 0.1, 0.0, 90.0}),
        arguments(N, T, new double[] {5.0, 5.0, 0.0, 0.0, 0.01, 5.0, 5.0}),
        arguments(N, T, new double[] {0.0, 0.0, 0.0, 1.0}),
        arguments(N, T, new double[] {1.0}),
        arguments(N, T, new double[] {0.01, 0.01, 0.01, 0.97}),
        arguments(N, T, new double[] {1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}),
        arguments(N, T, new double[] {0.001, 0.002, 0.003, 0.004, 0.005}),
        arguments(N, T, new double[] {0.001, 0.002, 0.003, 0.004, 0.000001, 10.0}),
        arguments(N, T, new double[] {0.001, 1000.0, 0.003, 10000.0, 0.005}),
        arguments(N, T, IntStream.range(1, 10).mapToDouble(i -> i).toArray()),
        arguments(N, 0.09, IntStream.range(1, 100).mapToDouble(i -> 1.0).toArray()),
        arguments(N, 0.15, IntStream.range(1, 1000).mapToDouble(i -> 1.0).toArray()),
        arguments(10000000, 0.15, IntStream.range(1, 10000).mapToDouble(i -> 1.0).toArray()),
        arguments(100000000, 0.16, IntStream.range(1, 100000).mapToDouble(i -> 1.0).toArray()));
  }

  @ParameterizedTest
  @MethodSource("weightsProvider")
  public void testWeightedSampler(int trials, double tolerance, double[] weights) {
    Integer[] indices = IntStream.range(0, weights.length).boxed().toArray(Integer[]::new);
    Function<PseudoRandom, Integer> sampler = SamplingUtils.weightedSampler(indices, weights);

    PseudoRandom random = new SeededPseudoRandom(12345);
    int[] counts = new int[indices.length];
    for (int i = 0; i < trials; i++) {
      counts[sampler.apply(random)]++;
    }

    // Calculate expected probabilities that are proportional to the weights.
    double[] pExpected = new double[weights.length];
    double sum = 0.0;
    for (double w : weights) {
      sum += w;
    }
    for (int i = 0; i < weights.length; i++) {
      pExpected[i] = weights[i] / sum;
    }

    double tol = (double) trials / weights.length * tolerance; // 5% of expected count
    // Ensure that the frequencies are within 5% of the expected frequencies.
    for (int i = 0; i < weights.length; i++) {
      double expectedCount = trials * pExpected[i];
      assert Math.abs(counts[i] - expectedCount) < tol
          : String.format(
              "Count for index %d out of tolerance: got %d, expected ~%.2f",
              i, counts[i], expectedCount);
    }
  }
}
