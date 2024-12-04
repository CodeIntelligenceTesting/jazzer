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

package com.code_intelligence.jazzer.instrumentor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

/**
 * This benchmark compares the throughput of a typical fuzz target when instrumented with different
 * edge coverage instrumentation strategies and coverage map implementations.
 *
 * <p>The benchmark currently uses the OWASP json-sanitizer as its target, which has the following
 * desirable properties for a benchmark: - It is a reasonably sized project that does not consist of
 * many different classes. - It is very heavy on computation with a high density of branching. - It
 * is entirely CPU bound with no IO and does not call expensive methods from the standard library.
 * With these properties, results obtained from this benchmark should provide reasonable lower
 * bounds on the relative slowdown introduced by the various approaches to instrumentations.
 */
@State(Scope.Benchmark)
public class CoverageInstrumentationBenchmark {
  private static final String TARGET_CLASSNAME = "com.google.json.JsonSanitizer";
  private static final String TARGET_PACKAGE =
      TARGET_CLASSNAME.substring(0, TARGET_CLASSNAME.lastIndexOf('.'));
  private static final String TARGET_METHOD = "sanitize";
  private static final MethodType TARGET_TYPE = MethodType.methodType(String.class, String.class);

  // This is part of the benchmark's state and not a constant to prevent constant folding.
  String TARGET_ARG =
      "{\"foo\":1123987,\"bar\":[true, false],\"baz\":{\"foo\":\"132ä3\",\"bar\":1.123e-005}}";

  MethodHandle uninstrumented_sanitize;
  MethodHandle local_DirectByteBuffer_NeverZero_sanitize;
  MethodHandle staticMethod_DirectByteBuffer_NeverZero_sanitize;
  MethodHandle staticMethod_DirectByteBuffer2_NeverZero_sanitize;
  MethodHandle staticMethod_Unsafe_NeverZero_sanitize;
  MethodHandle staticMethod_Unsafe_NeverZero2_sanitize;
  MethodHandle staticMethod_Unsafe_NeverZeroBranchfree_sanitize;
  MethodHandle staticMethod_Unsafe_SimpleIncrement_sanitize;

  public static MethodHandle handleForTargetMethod(ClassLoader classLoader)
      throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException {
    Class<?> targetClass = classLoader.loadClass(TARGET_CLASSNAME);
    return MethodHandles.lookup().findStatic(targetClass, TARGET_METHOD, TARGET_TYPE);
  }

  public static MethodHandle instrumentWithStrategy(
      EdgeCoverageStrategy strategy, Class<?> coverageMapClass)
      throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException {
    if (strategy == null) {
      // Do not instrument the code by using the benchmark class' ClassLoader.
      return handleForTargetMethod(CoverageInstrumentationBenchmark.class.getClassLoader());
    }
    // It's fine to reuse a single instrumentor here as we don't want to know which class received
    // how many counters.
    Instrumentor instrumentor = new EdgeCoverageInstrumentor(strategy, coverageMapClass, 0);
    return handleForTargetMethod(new InstrumentingClassLoader(instrumentor, TARGET_PACKAGE));
  }

  @Setup
  public void instrumentWithStrategies()
      throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException {
    uninstrumented_sanitize = instrumentWithStrategy(null, null);
    local_DirectByteBuffer_NeverZero_sanitize =
        instrumentWithStrategy(
            DirectByteBufferStrategy.INSTANCE, DirectByteBufferCoverageMap.class);
    staticMethod_DirectByteBuffer_NeverZero_sanitize =
        instrumentWithStrategy(new StaticMethodStrategy(), DirectByteBufferCoverageMap.class);
    staticMethod_DirectByteBuffer2_NeverZero_sanitize =
        instrumentWithStrategy(new StaticMethodStrategy(), DirectByteBuffer2CoverageMap.class);
    staticMethod_Unsafe_NeverZero_sanitize =
        instrumentWithStrategy(new StaticMethodStrategy(), UnsafeCoverageMap.class);
    staticMethod_Unsafe_NeverZero2_sanitize =
        instrumentWithStrategy(new StaticMethodStrategy(), Unsafe2CoverageMap.class);
    staticMethod_Unsafe_SimpleIncrement_sanitize =
        instrumentWithStrategy(new StaticMethodStrategy(), UnsafeSimpleIncrementCoverageMap.class);
    staticMethod_Unsafe_NeverZeroBranchfree_sanitize =
        instrumentWithStrategy(new StaticMethodStrategy(), UnsafeBranchfreeCoverageMap.class);
  }

  @Benchmark
  public String uninstrumented() throws Throwable {
    return (String) uninstrumented_sanitize.invokeExact(TARGET_ARG);
  }

  @Benchmark
  public String local_DirectByteBuffer_NeverZero() throws Throwable {
    return (String) local_DirectByteBuffer_NeverZero_sanitize.invokeExact(TARGET_ARG);
  }

  @Benchmark
  public String staticMethod_DirectByteBuffer_NeverZero() throws Throwable {
    return (String) staticMethod_DirectByteBuffer_NeverZero_sanitize.invokeExact(TARGET_ARG);
  }

  @Benchmark
  public String staticMethod_DirectByteBuffer2_NeverZero() throws Throwable {
    return (String) staticMethod_DirectByteBuffer2_NeverZero_sanitize.invokeExact(TARGET_ARG);
  }

  @Benchmark
  public String staticMethod_Unsafe_NeverZero() throws Throwable {
    return (String) staticMethod_Unsafe_NeverZero_sanitize.invokeExact(TARGET_ARG);
  }

  @Benchmark
  public String staticMethod_Unsafe_NeverZero2() throws Throwable {
    return (String) staticMethod_Unsafe_NeverZero2_sanitize.invokeExact(TARGET_ARG);
  }

  @Benchmark
  public String staticMethod_Unsafe_SimpleIncrement() throws Throwable {
    return (String) staticMethod_Unsafe_SimpleIncrement_sanitize.invokeExact(TARGET_ARG);
  }

  @Benchmark
  public String staticMethod_Unsafe_NeverZeroBranchfree() throws Throwable {
    return (String) staticMethod_Unsafe_NeverZeroBranchfree_sanitize.invokeExact(TARGET_ARG);
  }
}

class InstrumentingClassLoader extends ClassLoader {
  private final Instrumentor instrumentor;
  private final String classNamePrefix;

  InstrumentingClassLoader(Instrumentor instrumentor, String packageToInstrument) {
    super(InstrumentingClassLoader.class.getClassLoader());
    this.instrumentor = instrumentor;
    this.classNamePrefix = packageToInstrument + ".";
  }

  @Override
  public Class<?> loadClass(String name) throws ClassNotFoundException {
    if (!name.startsWith(classNamePrefix)) {
      return super.loadClass(name);
    }
    try (InputStream stream = super.getResourceAsStream(name.replace('.', '/') + ".class")) {
      if (stream == null) {
        throw new ClassNotFoundException(String.format("Failed to find class file for %s", name));
      }
      byte[] bytecode = readAllBytes(stream);
      byte[] instrumentedBytecode = instrumentor.instrument(name.replace('.', '/'), bytecode);
      return defineClass(name, instrumentedBytecode, 0, instrumentedBytecode.length);
    } catch (IOException e) {
      throw new ClassNotFoundException(String.format("Failed to read class file for %s", name), e);
    }
  }

  private static byte[] readAllBytes(InputStream in) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] buffer = new byte[64 * 104 * 1024];
    int read;
    while ((read = in.read(buffer)) != -1) {
      out.write(buffer, 0, read);
    }
    return out.toByteArray();
  }
}
