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
import static com.code_intelligence.jazzer.driver.OptParser.stringListSetting;
import static com.code_intelligence.jazzer.driver.OptParser.stringSetting;
import static com.code_intelligence.jazzer.driver.OptParser.uint64Setting;
import static java.lang.System.err;
import static java.lang.System.exit;
import static java.util.Collections.unmodifiableList;
import static java.util.Collections.unmodifiableSet;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;
import static java.util.stream.Stream.concat;

import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Static options that determine the runtime behavior of the fuzzer, set via Java properties.
 *
 * <p>Each option corresponds to a command-line argument of the driver of the same name.
 *
 * <p>Every public field should be deeply immutable.
 *
 * <p>This class is loaded twice: As it is used in {@link FuzzTargetRunner}, it is loaded in the
 * class loader that loads {@link Driver}. It is also used in
 * {@link com.code_intelligence.jazzer.agent.Agent} after the agent JAR has been added to the
 * bootstrap classpath and thus is loaded again in the bootstrap loader. This is not a problem since
 * it only provides immutable fields and has no non-fatal side effects.
 */
public final class Opt {
  static {
    // We additionally list system properties supported by the Jazzer JUnit engine that do not
    // directly map to arguments. These are not shown in help texts.
    ignoreSetting("instrument");
    ignoreSetting("valueprofile");
    // The following arguments are interpreted by the native launcher only. They do appear in the
    // help text, but aren't read by the driver.
    stringListSetting("cp", "The class path to use for fuzzing (native launcher only)");
    stringListSetting("jvm_args",
        "Arguments to pass to the JVM (separator can be escaped with '\\', native launcher only)");
    stringListSetting("additional_jvm_args",
        "Additional arguments to pass to the JVM (separator can be escaped with '\\', native launcher only)");
    stringSetting(
        "agent_path", null, "Custom path to jazzer_agent_deploy.jar (native launcher only)");
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
  public static final List<String> customHookIncludes = stringListSetting("custom_hook_includes",
      "Glob patterns matching names of classes to instrument with hooks (custom and built-in)");
  public static final List<String> customHookExcludes = stringListSetting("custom_hook_excludes",
      "Glob patterns matching names of classes that should not be instrumented with hooks (custom and built-in)");
  public static final List<String> customHooks =
      stringListSetting("custom_hooks", "Names of classes to load custom hooks from");
  public static final List<String> disabledHooks = stringListSetting("disabled_hooks",
      "Names of classes from which hooks (custom or built-in) should not be loaded from");
  public static final String dumpClassesDir = stringSetting(
      "dump_classes_dir", "", "Directory to dump instrumented .class files into (if non-empty)");
  public static final boolean hooks = boolSetting(
      "hooks", true, "Apply fuzzing instrumentation (use 'trace' for finer-grained control)");
  public static final String idSyncFile = stringSetting("id_sync_file", null, null);
  public static final List<String> instrumentationIncludes =
      stringListSetting("instrumentation_includes",
          "Glob patterns matching names of classes to instrument for fuzzing");
  public static final List<String> instrumentationExcludes =
      stringListSetting("instrumentation_excludes",
          "Glob patterns matching names of classes that should not be instrumented for fuzzing");
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

  // The values of this setting depends on autofuzz.
  public static final List<String> targetArgs = autofuzz.isEmpty()
      ? stringListSetting(
          "target_args", ' ', "Arguments to pass to the fuzz target's fuzzerInitialize method")
      : unmodifiableList(concat(Stream.of(autofuzz), autofuzzIgnore.stream()).collect(toList()));

  // Default to false if hooks is false to mimic the original behavior of the native fuzz target
  // runner, but still support hooks = false && dedup = true.
  public static final boolean dedup =
      boolSetting("dedup", hooks, "Compute and print a deduplication token for every finding");

  static final boolean mergeInner = boolSetting("internal.merge_inner", false, null);

  private static final boolean help =
      boolSetting("help", false, "Show this list of all available arguments");
  private static final boolean version = boolSetting("version", false, "Print version information");

  static {
    OptParser.failOnUnknownArgument();

    if (help) {
      err.println(OptParser.getHelpText());
      exit(0);
    }
    if (version) {
      err.printf("Jazzer v%s", JAZZER_VERSION);
      exit(0);
    }
    if (!targetClass.isEmpty() && !autofuzz.isEmpty()) {
      err.println("--target_class and --autofuzz cannot be specified together");
      exit(1);
    }
    if (!stringListSetting("target_args", ' ', null).isEmpty() && !autofuzz.isEmpty()) {
      err.println("--target_args and --autofuzz cannot be specified together");
      exit(1);
    }
    if (autofuzz.isEmpty() && !autofuzzIgnore.isEmpty()) {
      err.println("--autofuzz_ignore requires --autofuzz");
      exit(1);
    }
    if ((!ignore.isEmpty() || keepGoing > 1) && !dedup) {
      err.println("--nodedup is not supported with --ignore or --keep_going");
      exit(1);
    }
  }
}
