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
import static com.code_intelligence.jazzer.driver.OptParser.stringListSetting;
import static com.code_intelligence.jazzer.driver.OptParser.stringSetting;
import static com.code_intelligence.jazzer.driver.OptParser.uint64Setting;
import static java.lang.System.exit;

import com.code_intelligence.jazzer.utils.Log;
import java.util.List;
import java.util.Map;

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
    // The following arguments are interpreted by the native launcher only. They do appear in the
    // help text, but aren't read by the driver.
    stringListSetting("additional_jvm_args",
        "Additional arguments to pass to the JVM (separator can be escaped with '\\', native launcher only)");
    stringListSetting("jvm_args",
        "Arguments to pass to the JVM (separator can be escaped with '\\', native launcher only)");
  }

  public static final OptItem<List<String>> additionalClassesExcludes =
      stringListSetting("additional_classes_excludes",
          "Glob patterns matching names of classes from Java that are not in your jar file, "
              + "but may be included in your program");
  public static final OptItem<String> agentPath = stringSetting(
      "agent_path", "", "Custom path to jazzer_agent_deploy.jar (native launcher only)");
  public static final OptItem<String> androidBootclassClassesOverrides = stringSetting(
      "android_bootpath_classes_overrides", "",
      "Used for fuzzing classes loaded in through the bootstrap class loader on Android. Full path to jar file with the instrumented versions of the classes you want to override.");
  public static final OptItem<String> androidInitOptions = stringSetting("android_init_options", "",
      "Which libraries to use when initializing ART (native launcher only)");
  public static final OptItem<String> autofuzz = stringSetting("autofuzz", "",
      "Fully qualified reference (optionally with a Javadoc-style signature) to a "
          + "method on the class path to be fuzzed with automatically generated arguments "
          + "(examples: java.lang.System.out::println, java.lang.String::new(byte[]))");
  public static final OptItem<Boolean> asan = boolSetting(
      "asan", false, "Allow fuzzing of native libraries compiled with '-fsanitize=address'");
  public static final OptItem<List<String>> autofuzzIgnore = stringListSetting("autofuzz_ignore",
      ',', "Fully qualified names of exception classes to ignore during fuzzing");
  public static final OptItem<String> coverageDump = stringSetting("coverage_dump", "",
      "Path to write a JaCoCo .exec file to when the fuzzer exits (if non-empty)");
  public static final OptItem<String> coverageReport = stringSetting("coverage_report", "",
      "Path to write a human-readable coverage report to when the fuzzer exits (if non-empty)");
  public static final OptItem<List<String>> cp =
      stringListSetting("cp", "The class path to use for fuzzing (native launcher only)");
  public static final OptItem<List<String>> customHookExcludes = OptParser.stringListSetting(
      "custom_hook_excludes",
      "Glob patterns matching names of classes that should not be instrumented with hooks (custom and built-in)");
  public static final OptItem<List<String>> customHooks =
      stringListSetting("custom_hooks", "Names of classes to load custom hooks from");
  public static final OptItem<List<String>> customHookIncludes =
      OptParser.stringListSetting("custom_hook_includes",
          "Glob patterns matching names of classes to instrument with hooks (custom and built-in)");
  public static final OptItem<Boolean> dedup =
      boolSetting("dedup", true, "Compute and print a deduplication token for every finding");
  public static final OptItem<List<String>> disabledHooks = stringListSetting("disabled_hooks",
      "Names of classes from which hooks (custom or built-in) should not be loaded from");
  public static final OptItem<String> dumpClassesDir = stringSetting(
      "dump_classes_dir", "", "Directory to dump instrumented .class files into (if non-empty)");
  public static final OptItem<Boolean> experimentalMutator =
      boolSetting("experimental_mutator", false, "Use an experimental structured mutator");
  public static final OptItem<Long> experimentalCrossOverFrequency = uint64Setting(
      "experimental_cross_over_frequency", 100,
      "(Used in experimental mutator) Frequency of cross-over mutations actually being executed "
          + "when the cross-over function is picked by the underlying fuzzing engine (~1/2 of all mutations), "
          + "other invocations perform type specific mutations via the experimental mutator. "
          + "(0 = disabled, 1 = every call, 2 = every other call, etc.).");
  public static final OptItem<Boolean> fuzzNative = boolSetting("native", false,
      "Allow fuzzing of native libraries compiled with '-fsanitize=fuzzer' (implied by --asan and --ubsan)");
  public static final OptItem<Boolean> hooks = boolSetting(
      "hooks", true, "Apply fuzzing instrumentation (use 'trace' for finer-grained control)");
  public static final OptItem<Boolean> hwasan =
      boolSetting("hwasan", false, "Allow fuzzing of native libraries compiled with hwasan");
  public static final OptItem<String> idSyncFile = stringSetting("id_sync_file", "",
      "A file used by Jazzer subprocesses to coordinate coverage instrumented. If not set, "
          + "Jazzer will create a temporary file and pass it to subprocesses.");
  public static final OptItem<List<String>> ignore = stringListSetting("ignore", ',',
      "Hex strings representing deduplication tokens of findings that should be ignored");
  public static final OptItem<List<String>> instrumentationExcludes =
      OptParser.stringListSetting("instrumentation_excludes",
          "Glob patterns matching names of classes that should not be instrumented for fuzzing");
  public static final OptItem<List<String>> instrumentationIncludes =
      OptParser.stringListSetting("instrumentation_includes",
          "Glob patterns matching names of classes to instrument for fuzzing");
  public static final OptItem<Long> keepGoing = uint64Setting(
      "keep_going", 1, "Number of distinct findings after which the fuzzer should stop");
  public static final OptItem<String> reproducerPath = stringSetting("reproducer_path", ".",
      "Directory in which stand-alone Java reproducers are stored for each finding");
  public static final OptItem<List<String>> targetArgs = stringListSetting(
      "target_args", ' ', "Arguments to pass to the fuzz target's fuzzerInitialize method");
  public static final OptItem<String> targetClass = stringSetting("target_class", "",
      "Fully qualified name of the fuzz target class (required unless --autofuzz is specified)");
  // Used to disambiguate between multiple methods annotated with @FuzzTest in the target class.
  public static final OptItem<String> targetMethod = stringSetting("target_method", "",
      "The name of the @FuzzTest to execute in the class specified by --target_class");
  public static final OptItem<List<String>> trace = stringListSetting("trace",
      "Types of instrumentation to apply: cmp, cov, div, gep (disabled by default), indir, native");
  public static final OptItem<Boolean> ubsan = boolSetting(
      "ubsan", false, "Allow fuzzing of native libraries compiled with '-fsanitize=undefined'");

  // Internal options:

  // Whether this is a subprocess created by libFuzzer's `-merge` mode.
  public static final OptItem<Boolean> mergeInner = boolSetting("merge_inner", false, null);

  // Whether hook instrumentation should add a check for JazzerInternal#hooksEnabled before
  // executing hooks. Used to disable hooks during non-fuzz JUnit tests.
  public static final OptItem<Boolean> conditionalHooks =
      boolSetting("conditional_hooks", false, null);

  // Special driver options:

  private static final OptItem<Boolean> help =
      boolSetting("help", false, "Show this list of all available arguments");
  public static final OptItem<List<String>> instrumentOnly = stringListSetting("instrument_only",
      ',', "Comma separated list of jar files to instrument. No fuzzing is performed.");
  private static final OptItem<Boolean> version =
      boolSetting("version", false, "Print version information");

  public static void registerAndValidateCommandLineArgs(List<Map.Entry<String, String>> cliArgs) {
    OptParser.registerAndValidateCommandLineArgs(cliArgs);
  }

  public static void handleHelpAndVersionArgs() {
    if (help.get()) {
      Log.println(OptParser.getHelpText());
      exit(0);
    }
    if (version.get()) {
      Log.println("Jazzer v" + JAZZER_VERSION);
      exit(0);
    }
  }
}
