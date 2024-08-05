/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.instrumentor;

import static com.code_intelligence.jazzer.instrumentor.PatchTestUtils.*;
import static java.lang.invoke.MethodHandles.lookup;
import static java.lang.invoke.MethodType.methodType;

import com.code_intelligence.jazzer.runtime.CoverageMap;
import java.lang.invoke.*;
import java.nio.file.Files;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.*;

@Warmup(iterations = 10, time = 3)
@Measurement(iterations = 10, time = 3)
@Fork(value = 3)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@BenchmarkMode(Mode.AverageTime)
@State(Scope.Benchmark)
@SuppressWarnings("unused")
public class EdgeCoverageInstrumentation {
  private MethodHandle exampleMethod;

  @Setup
  public void setupInstrumentation() throws Throwable {
    String outDir = System.getenv("TEST_UNDECLARED_OUTPUTS_DIR");
    if (outDir == null || outDir.isEmpty()) {
      outDir =
          Files.createTempDirectory(EdgeCoverageInstrumentation.class.getSimpleName()).toString();
    }

    byte[] originalBytecode = classToBytecode(EdgeCoverageTarget.class);
    dumpBytecode(outDir, EdgeCoverageTarget.class.getName(), originalBytecode);

    byte[] patchedBytecode = applyInstrumentation(originalBytecode);
    dumpBytecode(outDir, EdgeCoverageTarget.class.getName() + ".patched", patchedBytecode);

    Class<?> patchedClass = bytecodeToClass(EdgeCoverageTarget.class.getName(), patchedBytecode);
    Object obj = lookup().findConstructor(patchedClass, methodType(void.class)).invoke();
    exampleMethod = lookup().bind(obj, "exampleMethod", methodType(List.class));
  }

  private byte[] applyInstrumentation(byte[] bytecode) {
    return new EdgeCoverageInstrumentor(new StaticMethodStrategy(), CoverageMap.class, 0)
        .instrument(EdgeCoverageTarget.class.getName().replace('.', '/'), bytecode);
  }

  @Benchmark
  public Object benchmarkInstrumentedMethodCall() throws Throwable {
    return exampleMethod.invoke();
  }
}
