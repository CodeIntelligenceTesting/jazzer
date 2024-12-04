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

package com.code_intelligence.jazzer.mutation;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.engine.SeededPseudoRandom;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.List;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

/**
 * This benchmark measures the overhead of the structured mutator on a very fast fuzz test. The two
 * benchmarked variants differ in whether they "detach" the mutated value in every iteration or
 * whether they serialize and then deserialize it instead. The latter is what we do currently, the
 * former is what we want to do in the future but requires patching libFuzzer.
 */
@BenchmarkMode(Mode.Throughput)
public class MutatorBenchmark {
  // Used to prevent any optimizations that would remove the fuzz test logic in case it is deemed
  // free of side effects (e.g. not throwing exceptions).
  static int blackhole;

  public static void fuzzMinimal(@NotNull List<@NotNull Byte> bytes) {
    // Simulate a minimal fuzz test that touches every element of the input.
    blackhole += bytes.stream().mapToInt(i -> i).sum();
  }

  @State(Scope.Benchmark)
  public static class BenchmarkState {
    @Param({"10", "100", "1000"})
    public int mutations;

    public ArgumentsMutator mutator;

    @Setup(Level.Iteration)
    public void setUp() throws NoSuchMethodException {
      mutator =
          ArgumentsMutator.forMethodOrThrow(
              MutatorBenchmark.class.getMethod("fuzzMinimal", List.class));
    }
  }

  @Benchmark
  public void mutateDetachInvoke(BenchmarkState state) throws Throwable {
    ArgumentsMutator mutator = state.mutator;
    PseudoRandom prng = new SeededPseudoRandom(12345678);
    mutator.init(prng);
    for (int i = 0; i < state.mutations; i++) {
      mutator.mutate(prng);
      mutator.invoke(null, true);
    }
  }

  @Benchmark
  public void mutateReadInvokeWrite(BenchmarkState state) throws Throwable {
    ArgumentsMutator mutator = state.mutator;
    PseudoRandom prng = new SeededPseudoRandom(12345678);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    mutator.init(prng);
    mutator.write(out);
    byte[] buffer = out.toByteArray();
    for (int i = 0; i < state.mutations; i++) {
      mutator.read(new ByteArrayInputStream(buffer));
      mutator.mutate(prng);
      out.reset();
      mutator.write(out);
      buffer = out.toByteArray();
      mutator.invoke(null, false);
    }
  }
}
