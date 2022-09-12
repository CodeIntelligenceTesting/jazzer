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
import static java.util.stream.Collectors.joining;

import com.code_intelligence.jazzer.agent.AgentInstaller;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.autofuzz.FuzzTarget;
import com.code_intelligence.jazzer.instrumentor.CoverageRecorder;
import com.code_intelligence.jazzer.runtime.FuzzTargetRunnerNatives;
import com.code_intelligence.jazzer.runtime.JazzerInternal;
import com.code_intelligence.jazzer.utils.UnsafeProvider;
import java.io.IOException;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Predicate;
import sun.misc.Unsafe;

/**
 * Executes a fuzz target and reports findings.
 *
 * <p>This class maintains global state (both native and non-native) and thus cannot be used
 * concurrently.
 */
public final class FuzzTargetRunner {
  static {
    AgentInstaller.install(Opt.hooks);
  }

  private static final String OPENTEST4J_TEST_ABORTED_EXCEPTION =
      "org.opentest4j.TestAbortedException";

  private static final Unsafe UNSAFE = UnsafeProvider.getUnsafe();
  private static final long BYTE_ARRAY_OFFSET = UNSAFE.arrayBaseOffset(byte[].class);

  // Default value of the libFuzzer -error_exitcode flag.
  private static final int LIBFUZZER_ERROR_EXIT_CODE = 77;

  // Possible return values for the libFuzzer callback runOne.
  private static final int LIBFUZZER_CONTINUE = 0;
  private static final int LIBFUZZER_RETURN_FROM_DRIVER = -2;

  private static final Set<Long> ignoredTokens = new HashSet<>(Opt.ignore);
  private static final FuzzedDataProviderImpl fuzzedDataProvider =
      FuzzedDataProviderImpl.withNativeData();
  private static final Class<?> fuzzTargetClass;
  private static final MethodHandle fuzzTargetMethod;
  private static final boolean useFuzzedDataProvider;
  // Reused in every iteration analogous to JUnit's PER_CLASS lifecycle.
  private static final Object fuzzTargetInstance;
  private static final Method fuzzerTearDown;
  private static final ReproducerTemplate reproducerTemplate;
  private static Predicate<Throwable> findingHandler;

  static {
    String targetClassName = FuzzTargetFinder.findFuzzTargetClassName();
    if (targetClassName == null) {
      err.println("Missing argument --target_class=<fuzz_target_class>");
      exit(1);
      throw new IllegalStateException("Not reached");
    }

    try {
      FuzzTargetRunner.class.getClassLoader().setDefaultAssertionStatus(true);
      fuzzTargetClass =
          Class.forName(targetClassName, false, FuzzTargetRunner.class.getClassLoader());
    } catch (ClassNotFoundException e) {
      err.printf(
          "ERROR: '%s' not found on classpath:%n%n%s%n%nAll required classes must be on the classpath specified via --cp.",
          targetClassName, System.getProperty("java.class.path"));
      exit(1);
      throw new IllegalStateException("Not reached");
    }
    // Inform the agent about the fuzz target class. Important note: This has to be done *before*
    // the class is initialized so that hooks can enable themselves in time for the fuzz target's
    // static initializer.
    JazzerInternal.onFuzzTargetReady(targetClassName);

    FuzzTargetFinder.FuzzTarget fuzzTarget;
    try {
      fuzzTarget = FuzzTargetFinder.findFuzzTarget(fuzzTargetClass);
    } catch (IllegalArgumentException e) {
      err.printf("ERROR: %s%n", e.getMessage());
      exit(1);
      throw new IllegalStateException("Not reached");
    }

    try {
      fuzzTargetMethod = MethodHandles.lookup().unreflect(fuzzTarget.method);
    } catch (IllegalAccessException e) {
      // Should have been made accessible in FuzzTargetFinder.
      throw new IllegalStateException(e);
    }
    useFuzzedDataProvider = fuzzTarget.useFuzzedDataProvider;
    fuzzerTearDown = fuzzTarget.tearDown.orElse(null);
    reproducerTemplate = new ReproducerTemplate(fuzzTargetClass.getName(), useFuzzedDataProvider);

    try {
      fuzzTargetInstance = fuzzTarget.newInstance.call();
    } catch (Throwable e) {
      err.print("== Java Exception during initialization: ");
      e.printStackTrace(err);
      exit(1);
      throw new IllegalStateException("Not reached");
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
    byte[] data;
    Object argument;
    if (useFuzzedDataProvider) {
      fuzzedDataProvider.setNativeData(dataPtr, dataLength);
      data = null;
      argument = fuzzedDataProvider;
    } else {
      data = copyToArray(dataPtr, dataLength);
      argument = data;
    }
    try {
      if (fuzzTargetInstance == null) {
        fuzzTargetMethod.invoke(argument);
      } else {
        fuzzTargetMethod.invoke(fuzzTargetInstance, argument);
      }
    } catch (Throwable uncaughtFinding) {
      finding = uncaughtFinding;
    }

    // When using libFuzzer's -merge flag, only the coverage of the current input is relevant, not
    // whether it is crashing. Since every crash would cause a restart of the process and thus the
    // JVM, we can optimize this case by not crashing.
    //
    // Incidentally, this makes the behavior of fuzz targets relying on global states more
    // consistent: Rather than resetting the global state after every crashing input and thus
    // dependent on the particular ordering of the inputs, we never reset it.
    if (Opt.mergeInner) {
      return LIBFUZZER_CONTINUE;
    }

    // Explicitly reported findings take precedence over uncaught exceptions.
    if (JazzerInternal.lastFinding != null) {
      finding = JazzerInternal.lastFinding;
      JazzerInternal.lastFinding = null;
    }
    // Allow skipping invalid inputs in fuzz tests by using e.g. JUnit's assumeTrue.
    if (finding == null || finding.getClass().getName().equals(OPENTEST4J_TEST_ABORTED_EXCEPTION)) {
      return LIBFUZZER_CONTINUE;
    }
    if (Opt.hooks) {
      finding = ExceptionUtils.preprocessThrowable(finding);
    }

    long dedupToken = Opt.dedup ? ExceptionUtils.computeDedupToken(finding) : 0;
    if (Opt.dedup && !ignoredTokens.add(dedupToken)) {
      return LIBFUZZER_CONTINUE;
    }

    if (findingHandler != null) {
      // We still print the libFuzzer crashing input information, which also dumps the crashing
      // input as a side effect.
      printCrashingInput();
      if (findingHandler.test(finding)) {
        return LIBFUZZER_CONTINUE;
      } else {
        return LIBFUZZER_RETURN_FROM_DRIVER;
      }
    }

    // The user-provided fuzz target method has returned. Any further exits are on us and should not
    // result in a "fuzz target exited" warning being printed by libFuzzer.
    temporarilyDisableLibfuzzerExitHook();

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
    // It doesn't support @FuzzTest fuzz targets, but these come with an integrated regression test
    // that satisfies the same purpose.
    if (fuzzTargetInstance == null) {
      dumpReproducer(data);
    }

    if (Long.compareUnsigned(ignoredTokens.size(), Opt.keepGoing) >= 0) {
      // Reached the maximum amount of findings to keep going for, crash after shutdown. We use
      // _Exit rather than System.exit to not trigger libFuzzer's exit handlers.
      if (!Opt.autofuzz.isEmpty() && Opt.dedup) {
        System.err.printf(
            "%nNote: To continue fuzzing past this particular finding, rerun with the following additional argument:"
                + "%n%n    --ignore=%s%n%n"
                + "To ignore all findings of this kind, rerun with the following additional argument:"
                + "%n%n    --autofuzz_ignore=%s%n",
            ignoredTokens.stream()
                .map(token -> Long.toUnsignedString(token, 16))
                .collect(joining(",")),
            finding.getClass().getName());
      }
      System.exit(LIBFUZZER_ERROR_EXIT_CODE);
      throw new IllegalStateException("Not reached");
    }
    return LIBFUZZER_CONTINUE;
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

  /**
   * Registers a custom handler for findings.
   *
   * @param findingHandler a consumer for the finding that returns true if the fuzzer should
   *     continue fuzzing and false
   *                       if it should return from {@link FuzzTargetRunner#startLibFuzzer(List)}.
   */
  public static void registerFindingHandler(Predicate<Throwable> findingHandler) {
    FuzzTargetRunner.findingHandler = findingHandler;
  }

  private static void shutdown() {
    if (!Opt.coverageDump.isEmpty() || !Opt.coverageReport.isEmpty()) {
      if (!Opt.coverageDump.isEmpty()) {
        CoverageRecorder.dumpJacocoCoverage(Opt.coverageDump);
      }
      if (!Opt.coverageReport.isEmpty()) {
        CoverageRecorder.dumpCoverageReport(Opt.coverageReport);
      }
    }

    if (fuzzerTearDown == null) {
      return;
    }
    err.println("calling fuzzerTearDown function");
    try {
      fuzzerTearDown.invoke(null);
    } catch (InvocationTargetException e) {
      // An exception in fuzzerTearDown is a regular finding.
      err.print("== Java Exception in fuzzerTearDown: ");
      e.getCause().printStackTrace(err);
      System.exit(LIBFUZZER_ERROR_EXIT_CODE);
    } catch (Throwable t) {
      // Any other exception is an error.
      t.printStackTrace(err);
      System.exit(1);
    }
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
        fuzzTargetMethod.invokeExact(recordingFuzzedDataProvider);
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
        System.exit(1);
        throw new IllegalStateException("Not reached");
      }
    } else {
      base64Data = Base64.getEncoder().encodeToString(data);
    }

    reproducerTemplate.dumpReproducer(base64Data, dataSha1);
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
  private static int startLibFuzzer(byte[][] args) {
    return FuzzTargetRunnerNatives.startLibFuzzer(args, FuzzTargetRunner.class);
  }

  /**
   * Causes libFuzzer to write the current input to disk as a crashing input and emit some
   * information about it to stderr.
   */
  private static void printCrashingInput() {
    FuzzTargetRunnerNatives.printCrashingInput();
  }

  /**
   * Disables libFuzzer's fuzz target exit detection until the next call to {@link #runOne}.
   *
   * <p>Calling {@link System#exit} after having called this method will not trigger libFuzzer's
   * exit hook that would otherwise print the "fuzz target exited" error message. This method should
   * thus only be called after control has returned from the user-provided fuzz target.
   */
  private static void temporarilyDisableLibfuzzerExitHook() {
    FuzzTargetRunnerNatives.temporarilyDisableLibfuzzerExitHook();
  }
}
