/*
 * Copyright 2023 Code Intelligence GmbH
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

import static com.code_intelligence.jazzer.driver.Constants.JAZZER_FINDING_EXIT_CODE;
import static com.code_intelligence.jazzer.runtime.Constants.IS_ANDROID;
import static java.lang.System.exit;
import static java.util.stream.Collectors.joining;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.autofuzz.FuzzTarget;
import com.code_intelligence.jazzer.instrumentor.CoverageRecorder;
import com.code_intelligence.jazzer.mutation.ArgumentsMutator;
import com.code_intelligence.jazzer.runtime.FuzzTargetRunnerNatives;
import com.code_intelligence.jazzer.runtime.JazzerInternal;
import com.code_intelligence.jazzer.utils.Log;
import com.code_intelligence.jazzer.utils.UnsafeProvider;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Stream;
import sun.misc.Unsafe;

/**
 * Executes a fuzz target and reports findings.
 *
 * <p>This class maintains global state (both native and non-native) and thus cannot be used
 * concurrently.
 */
public final class FuzzTargetRunner {
  private static final String OPENTEST4J_TEST_ABORTED_EXCEPTION =
      "org.opentest4j.TestAbortedException";

  private static final Unsafe UNSAFE = UnsafeProvider.getUnsafe();

  private static final long BYTE_ARRAY_OFFSET = UNSAFE.arrayBaseOffset(byte[].class);

  // Possible return values for the libFuzzer callback runOne.
  private static final int LIBFUZZER_CONTINUE = 0;
  private static final int LIBFUZZER_RETURN_FROM_DRIVER = -2;

  private static boolean invalidCorpusFileWarningShown = false;
  private static final Set<Long> ignoredTokens = new HashSet<>(Opt.ignore);
  private static final FuzzedDataProviderImpl fuzzedDataProvider =
      FuzzedDataProviderImpl.withNativeData();
  private static final MethodHandle fuzzTargetMethod;
  private static final boolean useFuzzedDataProvider;
  // Reused in every iteration analogous to JUnit's PER_CLASS lifecycle.
  private static final Object fuzzTargetInstance;
  private static final Method fuzzerTearDown;
  private static final ArgumentsMutator mutator;
  private static final ReproducerTemplate reproducerTemplate;
  private static Predicate<Throwable> findingHandler;

  static {
    FuzzTargetHolder.FuzzTarget fuzzTarget = FuzzTargetHolder.fuzzTarget;
    Class<?> fuzzTargetClass = fuzzTarget.method.getDeclaringClass();

    // The method may not be accessible - JUnit test classes and methods are usually declared
    // without access modifiers and thus package-private.
    fuzzTarget.method.setAccessible(true);
    try {
      fuzzTargetMethod = MethodHandles.lookup().unreflect(fuzzTarget.method);
    } catch (IllegalAccessException e) {
      throw new IllegalStateException(e);
    }
    useFuzzedDataProvider = fuzzTarget.usesFuzzedDataProvider();
    if (!useFuzzedDataProvider && IS_ANDROID) {
      Log.error("Android fuzz targets must use " + FuzzedDataProvider.class.getName());
      exit(1);
      throw new IllegalStateException("Not reached");
    }

    fuzzerTearDown = fuzzTarget.tearDown.orElse(null);
    reproducerTemplate = new ReproducerTemplate(fuzzTargetClass.getName(), useFuzzedDataProvider);

    JazzerInternal.onFuzzTargetReady(fuzzTargetClass.getName());

    try {
      fuzzTargetInstance = fuzzTarget.newInstance.call();
    } catch (Throwable t) {
      Log.finding(t);
      exit(1);
      throw new IllegalStateException("Not reached");
    }

    if (Opt.experimentalMutator) {
      if (Modifier.isStatic(fuzzTarget.method.getModifiers())) {
        mutator = ArgumentsMutator.forStaticMethodOrThrow(fuzzTarget.method);
      } else {
        mutator = ArgumentsMutator.forInstanceMethodOrThrow(fuzzTargetInstance, fuzzTarget.method);
      }
      Log.info("Using experimental mutator: " + mutator);
    } else {
      mutator = null;
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
   * @param dataPtr    a native pointer to beginning of the input provided by the fuzzer for this
   *                   execution
   * @param dataLength length of the fuzzer input
   * @return the value that the native LLVMFuzzerTestOneInput function should return. Currently,
   * this is always 0. The function may exit the process instead of returning.
   */
  private static int runOne(long dataPtr, int dataLength) {
    Throwable finding = null;
    byte[] data;
    Object argument;
    if (Opt.experimentalMutator) {
      // TODO: Instead of copying the native data and then reading it in, consider the following
      //  optimizations if they turn out to be worthwhile in benchmarks:
      //  1. Let libFuzzer pass in a null pointer if the byte array hasn't changed since the last
      //     call to our custom mutator and skip the read entirely.
      //  2. Implement a InputStream backed by Unsafe to avoid the copyToArray overhead.
      byte[] buf = copyToArray(dataPtr, dataLength);
      boolean readExactly = mutator.read(new ByteArrayInputStream(buf));

      // All inputs constructed by the mutator framework can be read exactly, existing corpus files
      // may not be valid for the current fuzz target anymore, though. In this case, print a warning
      // once.
      if (!(invalidCorpusFileWarningShown || readExactly || isFixedLibFuzzerInput(buf))) {
        invalidCorpusFileWarningShown = true;
        Log.warn("Some files in the seed corpus do not match the fuzz target signature. "
            + "This indicates that they were generated with a different signature and may cause issues reproducing previous findings.");
      }
      data = null;
      argument = null;
    } else if (useFuzzedDataProvider) {
      fuzzedDataProvider.setNativeData(dataPtr, dataLength);
      data = null;
      argument = fuzzedDataProvider;
    } else {
      data = copyToArray(dataPtr, dataLength);
      argument = data;
    }
    try {
      if (Opt.experimentalMutator) {
        // No need to detach as we are currently reading in the mutator state from bytes in every
        // iteration.
        mutator.invoke(false);
      } else if (fuzzTargetInstance == null) {
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

    Log.finding(finding);
    if (Opt.dedup) {
      // Has to be printed to stdout as it is parsed by libFuzzer when minimizing a crash. It does
      // not necessarily have to appear at the beginning of a line.
      // https://github.com/llvm/llvm-project/blob/4c106c93eb68f8f9f201202677cd31e326c16823/compiler-rt/lib/fuzzer/FuzzerDriver.cpp#L342
      Log.structuredOutput(String.format(Locale.ROOT, "DEDUP_TOKEN: %016x", dedupToken));
    }
    Log.println("== libFuzzer crashing input ==");
    printCrashingInput();
    // dumpReproducer needs to be called after libFuzzer printed its final stats as otherwise it
    // would report incorrect coverage - the reproducer generation involved rerunning the fuzz
    // target.
    // It doesn't support @FuzzTest fuzz targets, but these come with an integrated regression test
    // that satisfies the same purpose.
    // It also doesn't support the experimental mutator yet as that requires implementing Java code
    // generation for mutators.
    if (fuzzTargetInstance == null && !Opt.experimentalMutator) {
      dumpReproducer(data);
    }

    if (!Opt.dedup || Long.compareUnsigned(ignoredTokens.size(), Opt.keepGoing) >= 0) {
      // Reached the maximum amount of findings to keep going for, crash after shutdown. We use
      // _Exit rather than System.exit to not trigger libFuzzer's exit handlers.
      if (!Opt.autofuzz.isEmpty() && Opt.dedup) {
        Log.println("");
        Log.info(String.format(
            "To continue fuzzing past this particular finding, rerun with the following additional argument:"
                + "%n%n    --ignore=%s%n%n"
                + "To ignore all findings of this kind, rerun with the following additional argument:"
                + "%n%n    --autofuzz_ignore=%s",
            ignoredTokens.stream()
                .map(token -> Long.toUnsignedString(token, 16))
                .collect(joining(",")),
            Stream.concat(Opt.autofuzzIgnore.stream(), Stream.of(finding.getClass().getName()))
                .collect(joining(","))));
      }
      System.exit(JAZZER_FINDING_EXIT_CODE);
      throw new IllegalStateException("Not reached");
    }
    return LIBFUZZER_CONTINUE;
  }

  private static boolean isFixedLibFuzzerInput(byte[] input) {
    // Detect special libFuzzer inputs which can not be processed by the mutator framework.
    // libFuzzer always uses an empty input, and one with a single line feed (10) to indicate
    // end of initial corpus file processing.
    return input.length == 0 || (input.length == 1 && input[0] == 10);
  }

  // Called via JNI, being passed data from LLVMFuzzerCustomMutator.
  @SuppressWarnings("unused")
  private static int mutateOne(long data, int size, int maxSize, int seed) {
    mutate(data, size, seed);
    return writeToMemory(mutator, data, maxSize);
  }

  private static void mutate(long data, int size, int seed) {
    // libFuzzer sends the input "\n" when there are no corpus entries. We use that as a signal to
    // initialize the mutator instead of just reading that trivial input to produce a more
    // interesting value.
    if (size == 1 && UNSAFE.getByte(data) == '\n') {
      mutator.init(seed);
    } else {
      // TODO: See the comment on earlier calls to read for potential optimizations.
      mutator.read(new ByteArrayInputStream(copyToArray(data, size)));
      mutator.mutate(seed);
    }
  }

  private static long crossOverCount = 0;

  // Called via JNI, being passed data from LLVMFuzzerCustomCrossOver.
  @SuppressWarnings("unused")
  private static int crossOver(
      long data1, int size1, long data2, int size2, long out, int maxOutSize, int seed) {
    // Custom cross over and custom mutate are the only mutators registered in
    // libFuzzer, hence cross over is picked as often as mutate, which is way
    // too frequently. Without custom mutate, cross over would be picked from
    // the list of default mutators, so ~1/12 of the time. This also seems too
    // much and is reduced to a configurable frequency, default 1/100, here,
    // mutate is used in the other cases.
    if (Opt.experimentalCrossOverFrequency != 0
        && crossOverCount++ % Opt.experimentalCrossOverFrequency == 0) {
      mutator.crossOver(new ByteArrayInputStream(copyToArray(data1, size1)),
          new ByteArrayInputStream(copyToArray(data2, size2)), seed);
    } else {
      mutate(data1, size1, seed);
    }
    return writeToMemory(mutator, out, maxOutSize);
  }

  @SuppressWarnings("SameParameterValue")
  private static int writeToMemory(ArgumentsMutator mutator, long out, int maxOutSize) {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    // TODO: Instead of writing to a byte array and then copying that array's contents into
    //  memory, consider introducing an OutputStream backed by Unsafe.
    mutator.write(baos);
    byte[] mutatedBytes = baos.toByteArray();
    int newSize = Math.min(mutatedBytes.length, maxOutSize);
    UNSAFE.copyMemory(mutatedBytes, BYTE_ARRAY_OFFSET, null, out, newSize);
    return newSize;
  }

  /*
   * Starts libFuzzer via LLVMFuzzerRunDriver.
   */
  public static int startLibFuzzer(List<String> args) {
    // We always define LLVMFuzzerCustomMutator, but only use it when --experimental_mutator is
    // specified. libFuzzer contains logic that disables --len_control when it finds the custom
    // mutator symbol:
    // https://github.com/llvm/llvm-project/blob/da3623de2411dd931913eb510e94fe846c929c24/compiler-rt/lib/fuzzer/FuzzerDriver.cpp#L202-L207
    // We thus have to explicitly set --len_control to its default value when not using the new
    // mutator.
    // TODO: libFuzzer still emits a message about --len_control being disabled by default even if
    //  we override it via a flag. We may want to patch this out.
    if (!Opt.experimentalMutator) {
      // args may not be mutable.
      args = new ArrayList<>(args);
      // https://github.com/llvm/llvm-project/blob/da3623de2411dd931913eb510e94fe846c929c24/compiler-rt/lib/fuzzer/FuzzerFlags.def#L19
      args.add("-len_control=100");
    }

    for (String arg : args.subList(1, args.size())) {
      if (!arg.startsWith("-")) {
        Log.info("using inputs from: " + arg);
      }
    }

    if (!IS_ANDROID) {
      SignalHandler.initialize();
    }
    return startLibFuzzer(
        args.stream().map(str -> str.getBytes(StandardCharsets.UTF_8)).toArray(byte[][] ::new));
  }

  /**
   * Registers a custom handler for findings.
   *
   * @param findingHandler a consumer for the finding that returns true if the fuzzer should
   *                       continue fuzzing and false if it should return from
   *                       {@link FuzzTargetRunner#startLibFuzzer(List)}.
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
    Log.info("calling fuzzerTearDown function");
    try {
      fuzzerTearDown.invoke(null);
    } catch (InvocationTargetException e) {
      Log.finding(e.getCause());
      System.exit(JAZZER_FINDING_EXIT_CODE);
    } catch (Throwable t) {
      Log.error(t);
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
          Log.warn("Failed to reproduce crash when rerunning with recorder");
        }
      } catch (Throwable ignored) {
        // Expected.
      }
      try {
        base64Data = RecordingFuzzedDataProvider.serializeFuzzedDataProviderProxy(
            recordingFuzzedDataProvider);
      } catch (IOException e) {
        Log.error("Failed to create reproducer", e);
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
    return FuzzTargetRunnerNatives.startLibFuzzer(
        args, FuzzTargetRunner.class, Opt.experimentalMutator);
  }

  /**
   * Causes libFuzzer to write the current input to disk as a crashing input and emit some
   * information about it to stderr.
   */
  public static void printCrashingInput() {
    FuzzTargetRunnerNatives.printCrashingInput();
  }

  /**
   * Returns the debug string of the current mutator.
   * If no mutator is used, returns null.
   */
  public static String mutatorDebugString() {
    return mutator != null ? mutator.toString() : null;
  }

  /**
   * Returns whether the current mutator has detected invalid corpus files.
   * If no mutator is used, returns false.
   */
  public static boolean invalidCorpusFilesPresent() {
    return mutator != null && invalidCorpusFileWarningShown;
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
