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

import static com.code_intelligence.jazzer.Constants.JAZZER_VERSION;
import static com.code_intelligence.jazzer.driver.OptParser.boolSetting;
import static com.code_intelligence.jazzer.driver.OptParser.ignoreSetting;
import static com.code_intelligence.jazzer.driver.OptParser.lazyStringListSetting;
import static com.code_intelligence.jazzer.driver.OptParser.stringListSetting;
import static com.code_intelligence.jazzer.driver.OptParser.stringSetting;
import static com.code_intelligence.jazzer.driver.OptParser.uint64Setting;
import static java.lang.System.exit;
import static java.util.Collections.unmodifiableList;
import static java.util.Collections.unmodifiableSet;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;
import static java.util.stream.Stream.concat;

import com.code_intelligence.jazzer.utils.Log;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;

/**
 * Static options that determine the runtime behavior of the fuzzer, set via Java properties.
 *
 * <p>Each option corresponds to a command-line argument of the driver of the same name.
 *
 * <p>Every public field should be deeply immutable.
 */
public final class Opt {
  static {
    if (Opt.class.getClassLoader() == null) {
      throw new IllegalStateException("Opt should not be loaded in the bootstrap class loader");
    }
  }

  static {
    // We additionally list system properties supported by the Jazzer JUnit engine that do not
    // directly map to arguments. These are not shown in help texts.
    ignoreSetting("instrument");
    ignoreSetting("valueprofile");
    // The following arguments are interpreted by the native launcher only. They do appear in the
    // help text, but aren't read by the driver.
    stringListSetting("jvm_args",
        "Arguments to pass to the JVM (separator can be escaped with '\\', native launcher only)");
    stringListSetting("additional_jvm_args",
        "Additional arguments to pass to the JVM (separator can be escaped with '\\', native launcher only)");
    stringSetting(
        "agent_path", null, "Custom path to jazzer_agent_deploy.jar (native launcher only)");
    // The following arguments are interpreted by the Jazzer main class directly as they require
    // starting Jazzer as a subprocess.
    boolSetting(
        "asan", false, "Allow fuzzing of native libraries compiled with '-fsanitize=address'");
    boolSetting(
        "ubsan", false, "Allow fuzzing of native libraries compiled with '-fsanitize=undefined'");
    boolSetting("native", false,
        "Allow fuzzing of native libraries compiled with '-fsanitize=fuzzer' (implied by --asan and --ubsan)");
    // Options currently used by Android only
    stringSetting("android_init_options", null,
        "Which libraries to use when initializing ART (native launcher only)");
    boolSetting("hwasan", false, "Allow fuzzing of native libraries compiled with hwasan");
  }

  public static final String autofuzz = stringSetting("autofuzz", "",
      "Fully qualified reference (optionally with a Javadoc-style signature) to a "
          + "method on the class path to be fuzzed with automatically generated arguments "
          + "(examples: java.lang.System.out::println, java.lang.String::new(byte[]))");
  public static final List<String> autofuzzIgnore = stringListSetting("autofuzz_ignore", ',',
      "Fully qualified names of exception classes to ignore during fuzzing");
  public static final String coverageDump = stringSetting("coverage_dump", "",
      "Path to write a JaCoCo .exec file to when the fuzzer exits (if non-empty)");
  public static final String coverageReport = stringSetting("coverage_report", "",
      "Path to write a human-readable coverage report to when the fuzzer exits (if non-empty)");
  public static final List<String> customHooks =
      stringListSetting("custom_hooks", "Names of classes to load custom hooks from");
  public static final List<String> disabledHooks = stringListSetting("disabled_hooks",
      "Names of classes from which hooks (custom or built-in) should not be loaded from");
  public static final String dumpClassesDir = stringSetting(
      "dump_classes_dir", "", "Directory to dump instrumented .class files into (if non-empty)");
  public static final boolean experimentalMutator =
      boolSetting("experimental_mutator", false, "Use an experimental structured mutator");
  public static final long experimentalCrossOverFrequency = uint64Setting(
      "experimental_cross_over_frequency", 100,
      "(Used in experimental mutator) Frequency of cross-over mutations actually being executed "
          + "when the cross-over function is picked by the underlying fuzzing engine (~1/2 of all mutations), "
          + "other invocations perform type specific mutations via the experimental mutator. "
          + "(0 = disabled, 1 = every call, 2 = every other call, etc.).");
  public static final boolean hooks = boolSetting(
      "hooks", true, "Apply fuzzing instrumentation (use 'trace' for finer-grained control)");
  public static final String idSyncFile = stringSetting("id_sync_file", null, null);
  public static final Set<Long> ignore =
      unmodifiableSet(stringListSetting("ignore", ',',
          "Hex strings representing deduplication tokens of findings that should be ignored")
                          .stream()
                          .map(token -> Long.parseUnsignedLong(token, 16))
                          .collect(toSet()));
  public static final long keepGoing = uint64Setting(
      "keep_going", 1, "Number of distinct findings after which the fuzzer should stop");
  public static final String reproducerPath = stringSetting("reproducer_path", ".",
      "Directory in which stand-alone Java reproducers are stored for each finding");
  public static final String targetClass = stringSetting("target_class", "",
      "Fully qualified name of the fuzz target class (required unless --autofuzz is specified)");
  // Used to disambiguate between multiple methods annotated with @FuzzTest in the target class.
  public static final String targetMethod = stringSetting("target_method", "", null);
  public static final List<String> trace = stringListSetting("trace",
      "Types of instrumentation to apply: cmp, cov, div, gep (disabled by default), indir, native");

  // When Jazzer is executed from the command line, these settings are potentially modified by
  // JUnit's AgentConfigurator after the Driver has initialized Opt, which would result in stale
  // values being read if the settings weren't evaluated lazily.
  // TODO: Look into making all settings lazy, but verify that their value never changes after they
  //  have been read once.
  public static final Supplier<List<String>> customHookIncludes =
      lazyStringListSetting("custom_hook_includes",
          "Glob patterns matching names of classes to instrument with hooks (custom and built-in)");
  public static final Supplier<List<String>> customHookExcludes = lazyStringListSetting(
      "custom_hook_excludes",
      "Glob patterns matching names of classes that should not be instrumented with hooks (custom and built-in)");
  public static final Supplier<List<String>> instrumentationIncludes =
      lazyStringListSetting("instrumentation_includes",
          "Glob patterns matching names of classes to instrument for fuzzing");
  public static final Supplier<List<String>> instrumentationExcludes =
      lazyStringListSetting("instrumentation_excludes",
          "Glob patterns matching names of classes that should not be instrumented for fuzzing");
  // The values of this setting depends on autofuzz.
  public static final List<String> targetArgs = autofuzz.isEmpty()
      ? stringListSetting(
          "target_args", ' ', "Arguments to pass to the fuzz target's fuzzerInitialize method")
      : unmodifiableList(concat(Stream.of(autofuzz), autofuzzIgnore.stream()).collect(toList()));

  // Default to false if hooks is false to mimic the original behavior of the native fuzz target
  // runner, but still support hooks = false && dedup = true.
  public static final boolean dedup =
      boolSetting("dedup", hooks, "Compute and print a deduplication token for every finding");

  public static final String androidBootclassJarPath = stringSetting("android_bootclass_jar_path",
      null,
      "Full path to booclass jar path that will be used on Android runs. If you are using the launcher this will be set for you.");

  public static final String androidBootclassClassesOverrides = stringSetting(
      "android_bootpath_classes_overrides", null,
      "Used for fuzzing classes loaded in through the bootstrap class loader on Android. Full path to jar file with the instrumented versions of the classes you want to override.");

  // Whether hook instrumentation should add a check for JazzerInternal#hooksEnabled before
  // executing hooks. Used to disable hooks during non-fuzz JUnit tests.
  public static final boolean conditionalHooks =
      boolSetting("internal.conditional_hooks", false, null);

  static final boolean mergeInner = boolSetting("internal.merge_inner", false, null);

  private static final boolean help =
      boolSetting("help", false, "Show this list of all available arguments");
  private static final boolean version = boolSetting("version", false, "Print version information");

  // Methods below currently used by Android only
  public static final List<String> cp =
      stringListSetting("cp", "The class path to use for fuzzing (native launcher only)");

  public static final List<String> additionalClassesExcludes =
      stringListSetting("additional_classes_excludes",
          "Glob patterns matching names of classes from Java that are not in your jar file, "
              + "but may be included in your program");

  // Default to false. Sets if fuzzing is taking place on Android device (virtual or physical)
  public static final boolean isAndroid =
      boolSetting("android", false, "Jazzer is running on Android");

  // Some scenarios require instrumenting the jar before fuzzing begins
  public static final List<String> instrumentOnly = stringListSetting("instrument_only", ',',
      "Comma separated list of jar files to instrument. No fuzzing is performed.");

  static {
    OptParser.failOnUnknownArgument();

    if (help) {
      Log.println(OptParser.getHelpText());
      exit(0);
    }
    if (version) {
      Log.println("Jazzer v" + JAZZER_VERSION);
      exit(0);
    }
    if (!targetClass.isEmpty() && !autofuzz.isEmpty()) {
      Log.error("--target_class and --autofuzz cannot be specified together");
      exit(1);
    }
    if (!stringListSetting("target_args", ' ', null).isEmpty() && !autofuzz.isEmpty()) {
      Log.error("--target_args and --autofuzz cannot be specified together");
      exit(1);
    }
    if (autofuzz.isEmpty() && !autofuzzIgnore.isEmpty()) {
      Log.error("--autofuzz_ignore requires --autofuzz");
      exit(1);
    }
    if ((!ignore.isEmpty() || keepGoing > 1) && !dedup) {
      Log.error("--nodedup is not supported with --ignore or --keep_going");
      exit(1);
    }
    if (!instrumentOnly.isEmpty() && dumpClassesDir.isEmpty()) {
      Log.error("--dump_classes_dir must be set with --instrument_only");
      exit(1);
    }
  }
}
