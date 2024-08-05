/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.runtime;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 3)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@BenchmarkMode(Mode.AverageTime)
public class FuzzerCallbacksBenchmark {
  @State(Scope.Benchmark)
  public static class TraceCmpIntState {
    int arg1 = 0xCAFECAFE;
    int arg2 = 0xFEEDFEED;
    int pc = 0x12345678;
  }

  @Benchmark
  public void traceCmpInt(TraceCmpIntState state) {
    FuzzerCallbacks.traceCmpInt(state.arg1, state.arg2, state.pc);
  }

  @Benchmark
  public void traceCmpIntWithPc(TraceCmpIntState state) {
    FuzzerCallbacksWithPc.traceCmpInt(state.arg1, state.arg2, state.pc);
  }

  @Benchmark
  @Fork(jvmArgsAppend = {"-XX:+IgnoreUnrecognizedVMOptions", "-XX:+CriticalJNINatives"})
  public void traceCmpIntOptimizedCritical(TraceCmpIntState state) {
    FuzzerCallbacksOptimizedCritical.traceCmpInt(state.arg1, state.arg2, state.pc);
  }

  // Uncomment to benchmark Project Panama-backed implementation (requires JDK 16+).
  //  @Benchmark
  //  @Fork(jvmArgsAppend = {"--enable-native-access=ALL-UNNAMED", "--add-modules",
  //            "jdk.incubator.foreign"})
  //  public void
  //  traceCmpIntPanama(TraceCmpIntState state) throws Throwable {
  //    FuzzerCallbacksPanama.traceCmpInt(state.arg1, state.arg2, state.pc);
  //  }

  @State(Scope.Benchmark)
  public static class TraceSwitchState {
    @Param({"5", "10"})
    int numCases;

    long val;
    long[] cases;
    int pc = 0x12345678;

    @Setup
    public void setup() {
      cases = new long[2 + numCases];
      Random random = ThreadLocalRandom.current();
      Arrays.setAll(
          cases,
          i -> {
            switch (i) {
              case 0:
                return numCases;
              case 1:
                return 32;
              default:
                return random.nextInt();
            }
          });
      Arrays.sort(cases, 2, cases.length);
      val = random.nextInt();
    }
  }

  @Benchmark
  public void traceSwitch(TraceSwitchState state) {
    FuzzerCallbacks.traceSwitch(state.val, state.cases, state.pc);
  }

  @Benchmark
  public void traceSwitchWithPc(TraceSwitchState state) {
    FuzzerCallbacksWithPc.traceSwitch(state.val, state.cases, state.pc);
  }

  @Benchmark
  @Fork(jvmArgsAppend = {"-XX:+IgnoreUnrecognizedVMOptions", "-XX:+CriticalJNINatives"})
  public void traceSwitchOptimizedCritical(TraceSwitchState state) {
    FuzzerCallbacksOptimizedCritical.traceSwitch(state.val, state.cases, state.pc);
  }

  @Benchmark
  public void traceSwitchOptimizedNonCritical(TraceSwitchState state) {
    FuzzerCallbacksOptimizedNonCritical.traceSwitch(state.val, state.cases, state.pc);
  }

  // Uncomment to benchmark Project Panama-backed implementation (requires JDK 16+).
  //  @Benchmark
  //  @Fork(jvmArgsAppend = {"--enable-native-access=ALL-UNNAMED", "--add-modules",
  //            "jdk.incubator.foreign"})
  //  public void
  //  traceCmpSwitchPanama(TraceSwitchState state) throws Throwable {
  //    FuzzerCallbacksPanama.traceCmpSwitch(state.val, state.cases, state.pc);
  //  }

  @State(Scope.Benchmark)
  public static class TraceMemcmpState {
    @Param({"10", "100", "1000"})
    int length;

    byte[] array1;
    byte[] array2;
    int pc = 0x12345678;

    @Setup
    public void setup() {
      array1 = new byte[length];
      array2 = new byte[length];

      Random random = ThreadLocalRandom.current();
      random.nextBytes(array1);
      random.nextBytes(array2);
      // Make the arrays agree unil the midpoint to benchmark the "average"
      // case of an interesting memcmp.
      System.arraycopy(array1, 0, array2, 0, length / 2);
    }
  }

  @Benchmark
  public void traceMemcmp(TraceMemcmpState state) {
    FuzzerCallbacks.traceMemcmp(state.array1, state.array2, 1, state.pc);
  }

  @Benchmark
  @Fork(jvmArgsAppend = {"-XX:+IgnoreUnrecognizedVMOptions", "-XX:+CriticalJNINatives"})
  public void traceMemcmpOptimizedCritical(TraceMemcmpState state) {
    FuzzerCallbacksOptimizedCritical.traceMemcmp(state.array1, state.array2, 1, state.pc);
  }

  @Benchmark
  public void traceMemcmpOptimizedNonCritical(TraceMemcmpState state) {
    FuzzerCallbacksOptimizedNonCritical.traceMemcmp(state.array1, state.array2, 1, state.pc);
  }

  @State(Scope.Benchmark)
  public static class TraceStrstrState {
    @Param({"10", "100", "1000"})
    int length;

    @Param({"true", "false"})
    boolean asciiOnly;

    String haystack;
    String needle;
    int pc = 0x12345678;

    @Setup
    public void setup() {
      haystack = randomString(length, asciiOnly);
      needle = randomString(length, asciiOnly);
    }

    private String randomString(int length, boolean asciiOnly) {
      String asciiString =
          ThreadLocalRandom.current()
              .ints('a', 'z' + 1)
              .limit(length)
              .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
              .toString();
      if (asciiOnly) {
        return asciiString;
      }
      // Force String to be non-Latin-1 to preclude compact string optimization.
      return "\uFFFD" + asciiString.substring(1);
    }
  }

  @Benchmark
  public void traceStrstr(TraceStrstrState state) {
    FuzzerCallbacks.traceStrstr(state.haystack, state.needle, state.pc);
  }

  @Benchmark
  public void traceStrstrOptimizedNonCritical(TraceStrstrState state) {
    FuzzerCallbacksOptimizedNonCritical.traceStrstr(state.haystack, state.needle, state.pc);
  }

  @Benchmark
  @Fork(jvmArgsAppend = {"-XX:+IgnoreUnrecognizedVMOptions", "-XX:+CriticalJNINatives"})
  public void traceStrstrOptimizedJavaCritical(TraceStrstrState state)
      throws UnsupportedEncodingException {
    FuzzerCallbacksOptimizedCritical.traceStrstrJava(state.haystack, state.needle, state.pc);
  }

  @Benchmark
  public void traceStrstrOptimizedJavaNonCritical(TraceStrstrState state)
      throws UnsupportedEncodingException {
    FuzzerCallbacksOptimizedNonCritical.traceStrstrJava(state.haystack, state.needle, state.pc);
  }
}
