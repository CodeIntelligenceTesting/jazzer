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
import com.code_intelligence.jazzer.runtime.ExceptionUtils;
import com.code_intelligence.jazzer.runtime.FuzzedDataProviderImpl;
import com.code_intelligence.jazzer.runtime.JazzerInternal;
import com.code_intelligence.jazzer.runtime.ManifestUtils;
import com.code_intelligence.jazzer.runtime.RecordingFuzzedDataProvider;
import java.io.IOException;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Executes a fuzz target and reports findings.
 *
 * <p>This class maintains global state (both native and non-native) and thus cannot be used
 * concurrently.
 */
public final class FuzzTargetRunner {
  // Default value of the libFuzzer -error_exitcode flag.
  private static final int LIBFUZZER_ERROR_EXIT_CODE = 77;
  private static final String AUTOFUZZ_FUZZ_TARGET =
      "com.code_intelligence.jazzer.autofuzz.FuzzTarget";
  private static final String FUZZER_TEST_ONE_INPUT = "fuzzerTestOneInput";
  private static final String FUZZER_INITIALIZE = "fuzzerInitialize";
  private static final String FUZZER_TEARDOWN = "fuzzerTearDown";

  private static final Set<Long> ignoredTokens = new HashSet<>(Opt.ignore);
  private static final FuzzedDataProvider fuzzedDataProvider = new FuzzedDataProviderImpl();
  private static final Class<?> fuzzTargetClass;
  private static final MethodHandle fuzzTarget;
  public static final boolean useFuzzedDataProvider;
  private static final ReproducerTemplate reproducerTemplate;
  private static long runCount = 0;

  static {
    String targetClassName = determineFuzzTargetClassName();
    try {
      // When running with the agent, the JAR containing the agent and the driver has been added to
      // the bootstrap class loader path at the time the native driver can use FindClass to load the
      // Java fuzz target runner. As a result, FuzzTargetRunner's class loader will be the bootstrap
      // class loader, which doesn't have the fuzz target on its classpath. We thus have to
      // explicitly use the system class loader in this case.
      ClassLoader notBootstrapLoader = FuzzTargetRunner.class.getClassLoader();
      if (notBootstrapLoader == null) {
        notBootstrapLoader = ClassLoader.getSystemClassLoader();
      }
      fuzzTargetClass = Class.forName(targetClassName, false, notBootstrapLoader);
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
      CoverageRecorder.updateCoveredIdsWithCoverageMap();
    }

    Runtime.getRuntime().addShutdownHook(new Thread(FuzzTargetRunner::shutdown));
  }

  /**
   * Executes the user-provided fuzz target once.
   *
   * @param data the raw fuzzer input if using a {@code byte[]}-based fuzz target and {@code null}
   *             when using a {@link FuzzedDataProvider}-based fuzz target.
   * @return the value that the native LLVMFuzzerTestOneInput function should return. Currently,
   *         this is always 0. The function may exit the process instead of returning.
   */
  public static int runOne(byte[] data) {
    if (Opt.hooks && runCount < 2) {
      runCount++;
      // For the first two runs only, replay the coverage recorded from static initializers.
      // libFuzzer cleared the coverage map after they ran and could fail to see any coverage,
      // triggering an early exit, if we don't replay it here.
      // https://github.com/llvm/llvm-project/blob/957a5e987444d3193575d6ad8afe6c75da00d794/compiler-rt/lib/fuzzer/FuzzerLoop.cpp#L804-L809
      CoverageRecorder.replayCoveredIds();
    }

    Throwable finding = null;
    try {
      if (useFuzzedDataProvider) {
        // The FuzzedDataProvider has already been fed with the fuzzer input in
        // LLVMFuzzerTestOneInput.
        fuzzTarget.invokeExact(fuzzedDataProvider);
      } else {
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

    if (Opt.keepGoing == 1 || ignoredTokens.size() >= Opt.keepGoing) {
      // Reached the maximum amount of findings to keep going for, crash after shutdown. We use
      // _Exit rather than System.exit to not trigger libFuzzer's exit handlers.
      shutdown();
      _Exit(LIBFUZZER_ERROR_EXIT_CODE);
      throw new IllegalStateException("Not reached");
    }
    return 0;
  }

  public static void dumpAllStackTraces() {
    ExceptionUtils.dumpAllStackTraces();
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
      FuzzedDataProviderImpl.reset();
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
      FuzzedDataProviderImpl.reset();
      FuzzTarget.dumpReproducer(fuzzedDataProvider, Opt.reproducerPath, dataSha1);
      return;
    }

    String base64Data;
    if (useFuzzedDataProvider) {
      FuzzedDataProviderImpl.reset();
      FuzzedDataProvider recordingFuzzedDataProvider =
          RecordingFuzzedDataProvider.makeFuzzedDataProviderProxy();
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
