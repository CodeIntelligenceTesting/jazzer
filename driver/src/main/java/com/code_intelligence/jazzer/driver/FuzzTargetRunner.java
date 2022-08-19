/*
 * Copyright 2022 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.driver;

import static java.lang.System.err;
import static java.lang.System.exit;
import static java.lang.System.out;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.autofuzz.FuzzTarget;
import com.code_intelligence.jazzer.instrumentor.CoverageRecorder;
import com.code_intelligence.jazzer.runtime.CoverageMap;
import com.code_intelligence.jazzer.runtime.FuzzedDataProviderImpl;
import com.code_intelligence.jazzer.runtime.JazzerInternal;
import com.code_intelligence.jazzer.runtime.RecordingFuzzedDataProvider;
import com.code_intelligence.jazzer.runtime.SignalHandler;
import com.code_intelligence.jazzer.runtime.UnsafeProvider;
import com.code_intelligence.jazzer.utils.ExceptionUtils;
import com.code_intelligence.jazzer.utils.ManifestUtils;
import com.github.fmeum.rules_jni.RulesJni;
import java.io.IOException;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import sun.misc.Unsafe;

/**
 * Executes a fuzz target and reports findings.
 *
 * <p>This class maintains global state (both native and non-native) and thus cannot be used
 * concurrently.
 */
public final class FuzzTargetRunner {
  static {
    RulesJni.loadLibrary("jazzer_driver", FuzzTargetRunner.class);
  }

  private static final Unsafe UNSAFE = UnsafeProvider.getUnsafe();
  private static final long BYTE_ARRAY_OFFSET = UNSAFE.arrayBaseOffset(byte[].class);

  // Default value of the libFuzzer -error_exitcode flag.
  private static final int LIBFUZZER_ERROR_EXIT_CODE = 77;
  private static final String AUTOFUZZ_FUZZ_TARGET =
      "com.code_intelligence.jazzer.autofuzz.FuzzTarget";
  private static final String FUZZER_TEST_ONE_INPUT = "fuzzerTestOneInput";
  private static final String FUZZER_INITIALIZE = "fuzzerInitialize";
  private static final String FUZZER_TEARDOWN = "fuzzerTearDown";

  private static final Set<Long> ignoredTokens = new HashSet<>(Opt.ignore);
  private static final FuzzedDataProviderImpl fuzzedDataProvider =
      FuzzedDataProviderImpl.withNativeData();
  private static final Class<?> fuzzTargetClass;
  private static final MethodHandle fuzzTarget;
  public static final boolean useFuzzedDataProvider;
  private static final ReproducerTemplate reproducerTemplate;

  static {
    String targetClassName = determineFuzzTargetClassName();

    // FuzzTargetRunner is loaded by the bootstrap class loader since Driver installs the agent
    // before invoking FuzzTargetRunner.startLibFuzzer. We can't load the fuzz target with that
    // class loader - we have to use the class loader that loaded Driver. This would be
    // straightforward to do in Java 9+, but requires the use of reflection to maintain
    // compatibility with Java 8, which doesn't have StackWalker.
    //
    // Note that we can't just move the agent initialization so that FuzzTargetRunner is loaded by
    // Driver's class loader: The agent and FuzzTargetRunner have to share the native library that
    // contains libFuzzer and that library needs to be available in the bootstrap class loader
    // since instrumentation applied to Java standard library classes still needs to be able to call
    // libFuzzer hooks. A fundamental JNI restriction is that a native library can't be shared
    // between two different class loaders, so FuzzTargetRunner is thus forced to be loaded in the
    // bootstrap class loader, which makes this ugly code block necessary.
    // We also can't use the system class loader since Driver may be loaded by a custom class loader
    // if not invoked from the native driver.
    Class<?> driverClass;
    try {
      Class<?> reflectionClass = Class.forName("sun.reflect.Reflection");
      try {
        driverClass =
            (Class<?>) reflectionClass.getMethod("getCallerClass", int.class).invoke(null, 2);
      } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
        throw new IllegalStateException(e);
      }
    } catch (ClassNotFoundException e) {
      // sun.reflect.Reflection is no longer available after Java 8, use StackWalker.
      try {
        Class<?> stackWalker = Class.forName("java.lang.StackWalker");
        Class<? extends Enum<?>> stackWalkerOption =
            (Class<? extends Enum<?>>) Class.forName("java.lang.StackWalker$Option");
        Enum<?> retainClassReferences =
            Arrays.stream(stackWalkerOption.getEnumConstants())
                .filter(v -> v.name().equals("RETAIN_CLASS_REFERENCE"))
                .findFirst()
                .orElseThrow(()
                                 -> new IllegalStateException(
                                     "No RETAIN_CLASS_REFERENCE in java.lang.StackWalker$Option"));
        Object stackWalkerInstance = stackWalker.getMethod("getInstance", stackWalkerOption)
                                         .invoke(null, retainClassReferences);
        Method stackWalkerGetCallerClass = stackWalker.getMethod("getCallerClass");
        driverClass = (Class<?>) stackWalkerGetCallerClass.invoke(stackWalkerInstance);
      } catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException
          | InvocationTargetException ex) {
        throw new IllegalStateException(ex);
      }
    }

    try {
      ClassLoader driverClassLoader = driverClass.getClassLoader();
      driverClassLoader.setDefaultAssertionStatus(true);
      fuzzTargetClass = Class.forName(targetClassName, false, driverClassLoader);
    } catch (ClassNotFoundException e) {
      err.print("ERROR: ");
      e.printStackTrace(err);
      exit(1);
      throw new IllegalStateException("Not reached");
    }
    // Inform the agent about the fuzz target class. Important note: This has to be done *before*
    // the class is initialized so that hooks can enable themselves in time for the fuzz target's
    // static initializer.
    JazzerInternal.onFuzzTargetReady(targetClassName);

    Method bytesFuzzTarget = targetPublicStaticMethodOrNull(FUZZER_TEST_ONE_INPUT, byte[].class);
    Method dataFuzzTarget =
        targetPublicStaticMethodOrNull(FUZZER_TEST_ONE_INPUT, FuzzedDataProvider.class);
    if ((bytesFuzzTarget != null) == (dataFuzzTarget != null)) {
      err.printf(
          "ERROR: %s must define exactly one of the following two functions:%n", targetClassName);
      err.println("public static void fuzzerTestOneInput(byte[] ...)");
      err.println("public static void fuzzerTestOneInput(FuzzedDataProvider ...)");
      err.println(
          "Note: Fuzz targets returning boolean are no longer supported; exceptions should be thrown instead of returning true.");
      exit(1);
    }
    try {
      if (bytesFuzzTarget != null) {
        useFuzzedDataProvider = false;
        fuzzTarget = MethodHandles.publicLookup().unreflect(bytesFuzzTarget);
      } else {
        useFuzzedDataProvider = true;
        fuzzTarget = MethodHandles.publicLookup().unreflect(dataFuzzTarget);
      }
    } catch (IllegalAccessException e) {
      throw new RuntimeException(e);
    }
    reproducerTemplate = new ReproducerTemplate(fuzzTargetClass.getName(), useFuzzedDataProvider);

    Method initializeNoArgs = targetPublicStaticMethodOrNull(FUZZER_INITIALIZE);
    Method initializeWithArgs = targetPublicStaticMethodOrNull(FUZZER_INITIALIZE, String[].class);
    try {
      if (initializeWithArgs != null) {
        initializeWithArgs.invoke(null, (Object) Opt.targetArgs.toArray(new String[] {}));
      } else if (initializeNoArgs != null) {
        initializeNoArgs.invoke(null);
      }
    } catch (IllegalAccessException | InvocationTargetException e) {
      err.print("== Java Exception in fuzzerInitialize: ");
      e.printStackTrace(err);
      exit(1);
    }

    if (Opt.hooks) {
      // libFuzzer will clear the coverage map after this method returns and keeps no record of the
      // coverage accumulated so far (e.g. by static initializers). We record it here to keep it
      // around for JaCoCo coverage reports.
      CoverageRecorder.updateCoveredIdsWithCoverageMap();
    }

    Runtime.getRuntime().addShutdownHook(new Thread(FuzzTargetRunner::shutdown));
  }

  /**
   * A test-only convenience wrapper around {@link #runOne(long, int)}.
   */
  static int runOne(byte[] data) {
    long dataPtr = UNSAFE.allocateMemory(data.length);
    UNSAFE.copyMemory(data, BYTE_ARRAY_OFFSET, null, dataPtr, data.length);
    try {
      return runOne(dataPtr, data.length);
    } finally {
      UNSAFE.freeMemory(dataPtr);
    }
  }

  /**
   * Executes the user-provided fuzz target once.
   *
   * @param dataPtr a native pointer to beginning of the input provided by the fuzzer for this
   *     execution
   * @param dataLength length of the fuzzer input
   * @return the value that the native LLVMFuzzerTestOneInput function should return. Currently,
   *         this is always 0. The function may exit the process instead of returning.
   */
  private static int runOne(long dataPtr, int dataLength) {
    Throwable finding = null;
    byte[] data = null;
    try {
      if (useFuzzedDataProvider) {
        fuzzedDataProvider.setNativeData(dataPtr, dataLength);
        fuzzTarget.invokeExact((FuzzedDataProvider) fuzzedDataProvider);
      } else {
        data = copyToArray(dataPtr, dataLength);
        fuzzTarget.invokeExact(data);
      }
    } catch (Throwable uncaughtFinding) {
      finding = uncaughtFinding;
    }
    // Explicitly reported findings take precedence over uncaught exceptions.
    if (JazzerInternal.lastFinding != null) {
      finding = JazzerInternal.lastFinding;
      JazzerInternal.lastFinding = null;
    }
    if (finding == null) {
      return 0;
    }
    if (Opt.hooks) {
      finding = ExceptionUtils.preprocessThrowable(finding);
    }

    long dedupToken = Opt.dedup ? ExceptionUtils.computeDedupToken(finding) : 0;
    // Opt.keepGoing implies Opt.dedup.
    if (Opt.keepGoing > 1 && !ignoredTokens.add(dedupToken)) {
      return 0;
    }

    err.println();
    err.print("== Java Exception: ");
    finding.printStackTrace(err);
    if (Opt.dedup) {
      // Has to be printed to stdout as it is parsed by libFuzzer when minimizing a crash. It does
      // not necessarily have to appear at the beginning of a line.
      // https://github.com/llvm/llvm-project/blob/4c106c93eb68f8f9f201202677cd31e326c16823/compiler-rt/lib/fuzzer/FuzzerDriver.cpp#L342
      out.printf(Locale.ROOT, "DEDUP_TOKEN: %016x%n", dedupToken);
    }
    err.println("== libFuzzer crashing input ==");
    printCrashingInput();
    // dumpReproducer needs to be called after libFuzzer printed its final stats as otherwise it
    // would report incorrect coverage - the reproducer generation involved rerunning the fuzz
    // target.
    dumpReproducer(data);

    if (Opt.keepGoing == 1 || Long.compareUnsigned(ignoredTokens.size(), Opt.keepGoing) >= 0) {
      // Reached the maximum amount of findings to keep going for, crash after shutdown. We use
      // _Exit rather than System.exit to not trigger libFuzzer's exit handlers.
      shutdown();
      _Exit(LIBFUZZER_ERROR_EXIT_CODE);
      throw new IllegalStateException("Not reached");
    }
    return 0;
  }

  /*
   * Starts libFuzzer via LLVMFuzzerRunDriver.
   *
   * Note: Must be public rather than package-private as it is loaded in a different class loader
   * than Driver.
   */
  public static int startLibFuzzer(List<String> args) {
    SignalHandler.initialize();
    return startLibFuzzer(Utils.toNativeArgs(args));
  }

  private static void shutdown() {
    if (!Opt.coverageDump.isEmpty() || !Opt.coverageReport.isEmpty()) {
      int[] everCoveredIds = CoverageMap.getEverCoveredIds();
      if (!Opt.coverageDump.isEmpty()) {
        CoverageRecorder.dumpJacocoCoverage(everCoveredIds, Opt.coverageDump);
      }
      if (!Opt.coverageReport.isEmpty()) {
        CoverageRecorder.dumpCoverageReport(everCoveredIds, Opt.coverageReport);
      }
    }

    Method teardown = targetPublicStaticMethodOrNull(FUZZER_TEARDOWN);
    if (teardown == null) {
      return;
    }
    err.println("calling fuzzerTearDown function");
    try {
      teardown.invoke(null);
    } catch (InvocationTargetException e) {
      // An exception in fuzzerTearDown is a regular finding.
      err.print("== Java Exception in fuzzerTearDown: ");
      e.getCause().printStackTrace(err);
      _Exit(LIBFUZZER_ERROR_EXIT_CODE);
    } catch (Throwable t) {
      // Any other exception is an error.
      t.printStackTrace(err);
      _Exit(1);
    }
  }

  private static String determineFuzzTargetClassName() {
    if (!Opt.autofuzz.isEmpty()) {
      return AUTOFUZZ_FUZZ_TARGET;
    }
    if (!Opt.targetClass.isEmpty()) {
      return Opt.targetClass;
    }
    String manifestTargetClass = ManifestUtils.detectFuzzTargetClass();
    if (manifestTargetClass != null) {
      return manifestTargetClass;
    }
    err.println("Missing argument --target_class=<fuzz_target_class>");
    exit(1);
    throw new IllegalStateException("Not reached");
  }

  private static void dumpReproducer(byte[] data) {
    if (data == null) {
      assert useFuzzedDataProvider;
      fuzzedDataProvider.reset();
      data = fuzzedDataProvider.consumeRemainingAsBytes();
    }
    MessageDigest digest;
    try {
      digest = MessageDigest.getInstance("SHA-1");
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-1 not available", e);
    }
    String dataSha1 = toHexString(digest.digest(data));

    if (!Opt.autofuzz.isEmpty()) {
      fuzzedDataProvider.reset();
      FuzzTarget.dumpReproducer(fuzzedDataProvider, Opt.reproducerPath, dataSha1);
      return;
    }

    String base64Data;
    if (useFuzzedDataProvider) {
      fuzzedDataProvider.reset();
      FuzzedDataProvider recordingFuzzedDataProvider =
          RecordingFuzzedDataProvider.makeFuzzedDataProviderProxy(fuzzedDataProvider);
      try {
        fuzzTarget.invokeExact(recordingFuzzedDataProvider);
        if (JazzerInternal.lastFinding == null) {
          err.println("Failed to reproduce crash when rerunning with recorder");
        }
      } catch (Throwable ignored) {
        // Expected.
      }
      try {
        base64Data = RecordingFuzzedDataProvider.serializeFuzzedDataProviderProxy(
            recordingFuzzedDataProvider);
      } catch (IOException e) {
        err.print("ERROR: Failed to create reproducer: ");
        e.printStackTrace(err);
        // Don't let libFuzzer print a native stack trace.
        _Exit(1);
        throw new IllegalStateException("Not reached");
      }
    } else {
      base64Data = Base64.getEncoder().encodeToString(data);
    }

    reproducerTemplate.dumpReproducer(base64Data, dataSha1);
  }

  private static Method targetPublicStaticMethodOrNull(String name, Class<?>... parameterTypes) {
    try {
      Method method = fuzzTargetClass.getMethod(name, parameterTypes);
      if (!Modifier.isStatic(method.getModifiers()) || !Modifier.isPublic(method.getModifiers())) {
        return null;
      }
      return method;
    } catch (NoSuchMethodException e) {
      return null;
    }
  }

  /**
   * Convert a byte array to a lower-case hex string.
   *
   * <p>The returned hex string always has {@code 2 * bytes.length} characters.
   *
   * @param bytes the bytes to convert
   * @return a lower-case hex string representing the bytes
   */
  private static String toHexString(byte[] bytes) {
    String unpadded = new BigInteger(1, bytes).toString(16);
    int numLeadingZeroes = 2 * bytes.length - unpadded.length();
    return String.join("", Collections.nCopies(numLeadingZeroes, "0")) + unpadded;
  }

  // Accessed by fuzz_target_runner.cpp.
  @SuppressWarnings("unused")
  private static void dumpAllStackTraces() {
    ExceptionUtils.dumpAllStackTraces();
  }

  private static byte[] copyToArray(long ptr, int length) {
    // TODO: Use Unsafe.allocateUninitializedArray instead once Java 9 is the base.
    byte[] array = new byte[length];
    UNSAFE.copyMemory(null, ptr, array, BYTE_ARRAY_OFFSET, length);
    return array;
  }

  /**
   * Starts libFuzzer via LLVMFuzzerRunDriver.
   *
   * @param args command-line arguments encoded in UTF-8 (not null-terminated)
   * @return the return value of LLVMFuzzerRunDriver
   */
  private static native int startLibFuzzer(byte[][] args);

  /**
   * Causes libFuzzer to write the current input to disk as a crashing input and emit some
   * information about it to stderr.
   */
  private static native void printCrashingInput();

  /**
   * Immediately terminates the process without performing any cleanup.
   *
   * <p>Neither JVM shutdown hooks nor native exit handlers are called. This method does not return.
   *
   * <p>This method provides a way to exit Jazzer without triggering libFuzzer's exit hook that
   * prints the "fuzz target exited" error message. It should thus be preferred over
   * {@link System#exit} in any situation where Jazzer encounters an error after the fuzz target has
   * started running.
   *
   * @param exitCode the exit code
   */
  private static native void _Exit(int exitCode);
}
