/*
 * Copyright 2023 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.code_intelligence.jazzer.utils;

import static com.code_intelligence.jazzer.Constants.JAZZER_VERSION;
import static java.lang.System.exit;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.*;
import java.util.jar.Manifest;
import java.util.stream.Collectors;

/**
 * Config holds all configuration options for jazzer and handles loading them on startup.
 * <p>
 * Items will be automatically initialized via first looking at the manifest file and then looking
 * at environment variables with environment variables taking precedence over manifest file entries.
 * It also allows overriding values further at runtime so that command line args can be used but
 * that would need to be. This uses reflection to operate on all of its own fields at startup.
 */
public class Config {
  private static final String NAMESPACE_ROOT = "jazzer";

  private static final Set<ConfigItem<?>> knownOptions = new HashSet<>();

  // We additionally list system properties supported by the Jazzer JUnit engine that do not
  // directly map to arguments. These are not shown in help texts.
  public static final ConfigItem.StrList instrument = hiddenStrListItem("instrument", ',');
  public static final ConfigItem.Bool valueProfile = hiddenBoolItem("valueprofile", false);

  // The following arguments are interpreted by the native launcher only. They do appear in the
  // help text, but aren't read by the driver.
  public static final ConfigItem.StrList jvmArgs = strListItem("jvm_args", File.pathSeparatorChar,
      "Arguments to pass to the JVM (separator can be escaped with '\\\\', native launcher only)");
  public static final ConfigItem.StrList additionalJvmArgs = strListItem("additional_jvm_args",
      File.pathSeparatorChar,
      "Additional arguments to pass to the JVM (separator can be escaped with '\\', native launcher only)");
  public static final ConfigItem.Str agentPath =
      strItem("agent_path", "", "Custom path to jazzer_agent_deploy.jar (native launcher only)");
  // The following arguments are interpreted by the Jazzer main class directly as they require
  // starting Jazzer as a subprocess.
  public static final ConfigItem.Bool asan = boolItem(
      "asan", false, "Allow fuzzing of native libraries compiled with '-fsanitize=address'");
  public static final ConfigItem.Bool ubsan = boolItem(
      "ubsan", false, "Allow fuzzing of native libraries compiled with '-fsanitize=undefined'");
  public static final ConfigItem.Bool hwasan =
      boolItem("hwasan", false, "Allow fuzzing of native libraries compiled with hwasan");
  public static final ConfigItem.Bool fuzzNative = boolItem("native", false,
      "Allow fuzzing of native libraries compiled with '-fsanitize=fuzzer' (implied by --asan and --ubsan)");

  public static final ConfigItem.StrList cp = strListItem(
      "cp", File.pathSeparatorChar, "The class path to use for fuzzing (native launcher only)");
  public static final ConfigItem.Str autofuzz = strItem("autofuzz", "",
      "Fully qualified reference (optionally with a Javadoc-style signature) to a "
          + "method on the class path to be fuzzed with automatically generated arguments "
          + "(examples: java.lang.System.out::println, java.lang.String::new(byte[]))");
  public static final ConfigItem.StrList autofuzzIgnore = strListItem("autofuzz_ignore", ',',
      "Fully qualified names of exception classes to ignore during fuzzing");
  public static final ConfigItem.Str coverageDump = strItem("coverage_dump", "",
      "Path to write a JaCoCo .exec file to when the fuzzer exits (if non-empty)");
  public static final ConfigItem.Str coverageReport = strItem("coverage_report", "",
      "Path to write a human-readable coverage report to when the fuzzer exits (if non-empty)");
  public static final ConfigItem.StrList customHookIncludes =
      strListItem("custom_hook_includes", File.pathSeparatorChar,
          "Glob patterns matching names of classes to instrument with hooks (custom and built-in)");
  public static final ConfigItem.StrList customHookExcludes = strListItem("custom_hook_excludes",
      File.pathSeparatorChar,
      "Glob patterns matching names of classes that should not be instrumented with hooks (custom and built-in)");
  public static final ConfigItem.StrList customHooks = strListItem(
      "custom_hooks", File.pathSeparatorChar, "Names of classes to load custom hooks from");
  public static final ConfigItem.StrList disabledHooks =
      strListItem("disabled_hooks", File.pathSeparatorChar,
          "Names of classes from which hooks (custom or built-in) should not be loaded from");
  public static final ConfigItem.Str dumpClassesDir = strItem(
      "dump_classes_dir", "", "Directory to dump instrumented .class files into (if non-empty)");
  public static final ConfigItem.Bool experimentalMutator =
      boolItem("experimental_mutator", false, "Use an experimental structured mutator");
  public static final ConfigItem.Bool hooks = boolItem(
      "hooks", true, "Apply fuzzing instrumentation (use 'trace' for finer-grained control)");
  // TODO: this has no description in the original but it would be good to either give it one or
  // have it be hidden
  public static final ConfigItem.Str idSyncFile = strItem("id_sync_file", "", "");
  public static final ConfigItem.StrList instrumentationIncludes =
      strListItem("instrumentation_includes", File.pathSeparatorChar,
          "Glob patterns matching names of classes to instrument for fuzzing");
  public static final ConfigItem.StrList instrumentationExcludes =
      strListItem("instrumentation_excludes", File.pathSeparatorChar,
          "Glob patterns matching names of classes that should not be instrumented for fuzzing");
  public static final ConfigItem.StrList additionalClassesExcludes =
      strListItem("additional_classes_excludes", File.pathSeparatorChar,
          "Glob patterns matching names of classes from Java that are not in your jar file, "
              + "but may be included in your program");
  public static final ConfigItem.HexSet ignore = hexSetItem("ignore", ',',
      "Hex strings representing deduplication tokens of findings that should be ignored");
  public static final ConfigItem.Uint64 keepGoing =
      uint64Item("keep_going", 1, "Number of distinct findings after which the fuzzer should stop");
  public static final ConfigItem.Str reproducerPath = strItem("reproducer_path", ".",
      "Directory in which stand-alone Java reproducers are stored for each finding");
  public static final ConfigItem.Str targetClass = strItem("target_class", "",
      "Fully qualified name of the fuzz target class (required unless --autofuzz is specified)");
  public static final ConfigItem.Str targetMethod = strItem("target_method", "",
      "Used to disambiguate between multiple methods annotated with @FuzzTest in the target class");
  public static final ConfigItem.StrList trace = strListItem("trace", File.pathSeparatorChar,
      "Types of instrumentation to apply: cmp, cov, div, gep (disabled by default), indir, native");

  // The values of this setting depends on autofuzz.
  // TODO: If autofuzz is set, this will be overriden by the autofuzz setting in `loadConfig`
  public static final ConfigItem.StrList targetArgs = strListItem(
      "target_args", ' ', "Arguments to pass to the fuzz target's fuzzerInitialize method");

  // TODO: this defaults to whatever `hooks` is set to
  public static final ConfigItem.Bool dedup =
      boolItem("dedup", false, "Compute and print a deduplication token for every finding");

  public static final ConfigItem.Bool isAndroid =
      boolItem("android", false, "Jazzer is running on Android");

  public static final ConfigItem.Bool conditionalHooks = boolItem(
      Arrays.asList("internal", "conditional_hooks"), false,
      "whether hook instrumentation should check JazzerInternal#hooksEnabled before executing hooks. "
          + "Used to disable hooks during non-fuzz JUnit tests");

  public static final ConfigItem.StrList instrumentOnly = strListItem("instrument_only", ',',
      "Comma separated list of jar files to instrument. No fuzzing is performed.");

  public static final ConfigItem.Bool mergeInner =
      boolItem(Arrays.asList("internal", "merge_inner"), false, "");

  private static final ConfigItem.Bool help =
      boolItem("help", false, "Show this list of all available arguments");

  private static final ConfigItem.Bool version =
      boolItem("version", false, "Print version information");

  /**
   * Loads the config variables from the passed in command line args, environment variables, and
   * manifest file entries. {@code Config} assumes that this is only called once and is the only way
   * that these values will be modified.
   * @param args An array of command line args
   */
  public static void loadConfig(List<String> args) {
    // Check if the config has already been loaded, if so end because we're assuming that the
    // configuration should be the same
    // TODO: maybe this can use be a configitem? But having just a handle of special cases is
    // probably fine
    if (System.getProperty("jazzer.config-loaded") != null) {
      return;
    }

    loadFromManifest();
    loadFromEnv();
    Map<String, String> cliArgs = processJazzerCli(args);
    knownOptions.forEach(item -> {
      String value = cliArgs.get(item.getManifestName());
      if (value != null) {
        item.setFromString(value);
      }
    });

    // --asan and --ubsan imply --native by default, but --native can also be used by itself to fuzz
    // native libraries without sanitizers (e.g. to quickly grow a corpus).
    if (!fuzzNative.isSet()) {
      fuzzNative.set(asan.get() || ubsan.get() || hwasan.get());
    }

    System.setProperty("jazzer.config-loaded", "true");

    if (help.get()) {
      Log.println(getHelpText());
      exit(0);
    }
    if (version.get()) {
      Log.println("Jazzer v" + JAZZER_VERSION);
      exit(0);
    }
    if (!targetClass.get().isEmpty() && !autofuzz.get().isEmpty()) {
      Log.error("--target_class and --autofuzz cannot be specified together");
      exit(1);
    }
    if (!targetArgs.get().isEmpty() && !autofuzz.get().isEmpty()) {
      Log.error("--target_args and --autofuzz cannot be specified together");
      exit(1);
    }
    if (autofuzz.get().isEmpty() && !autofuzzIgnore.get().isEmpty()) {
      Log.error("--autofuzz_ignore requires --autofuzz");
      exit(1);
    }
    if ((!ignore.get().isEmpty() || keepGoing.get() > 1) && !dedup.get()) {
      Log.error("--nodedup is not supported with --ignore or --keep_going");
      exit(1);
    }
    if (!instrumentOnly.get().isEmpty() && dumpClassesDir.get().isEmpty()) {
      Log.error("--dump_classes_dir must be set with --instrument_only");
      exit(1);
    }
    // this case will only happen if any of the `*san`s are true and native was not set by anything
    if ((asan.get() || ubsan.get() || hwasan.get()) && !fuzzNative.get()) {
      Log.error("--asan, --hwasan and --ubsan cannot be used without --native");
      exit(1);
    }
  }

  private static void loadFromManifest() {
    try {
      Enumeration<URL> manifests =
          Config.class.getClassLoader().getResources("META-INF/MANIFEST.MF");
      while (manifests.hasMoreElements()) {
        URL manifestUrl = manifests.nextElement();
        try (InputStream inputStream = manifestUrl.openStream()) {
          Manifest manifest = new Manifest(inputStream);

          knownOptions.forEach(item -> {
            String value = manifest.getMainAttributes().getValue(item.getManifestName());
            if (value != null) {
              item.setFromString(value);
            }
          });
        }
      }
    } catch (IOException e) {
      // TODO: should this throw an exception or simply keep going?
      throw new RuntimeException(e);
    }
  }

  private static void loadFromEnv() {
    knownOptions.forEach(item -> {
      String value = System.getenv(item.getEnvName());
      if (value != null) {
        item.setFromString(value);
      }
    });
  }

  private static String getHelpText() {
    return knownOptions.stream()
        .map(ConfigItem::description)
        .filter(Optional::isPresent)
        .map(Optional::get)
        .collect(Collectors.joining("\n"));
  }

  private static Map<String, String> processJazzerCli(List<String> args) {
    return args.stream()
        .filter(arg -> arg.startsWith("--"))
        .map(arg -> arg.substring("--".length()))
        // Filter out "--", which can be used to declare that all further arguments aren't libFuzzer
        // arguments.
        .filter(arg -> !arg.isEmpty())
        .map(Config::parseSingleArg)
        .collect(
            Collectors.toMap(AbstractMap.SimpleEntry::getKey, AbstractMap.SimpleEntry::getValue));
  }

  private static AbstractMap.SimpleEntry<String, String> parseSingleArg(String arg) {
    String[] nameAndValue = arg.split("=", 2);
    if (nameAndValue.length == 2) {
      // Example: --keep_going=10 --> (keep_going, 10)
      return new AbstractMap.SimpleEntry<>(nameAndValue[0], nameAndValue[1]);
    } else if (nameAndValue[0].startsWith("no")) {
      // Example: --nohooks --> (hooks, "false")
      return new AbstractMap.SimpleEntry<>(nameAndValue[0].substring("no".length()), "false");
    } else {
      // Example: --dedup --> (dedup, "true")
      return new AbstractMap.SimpleEntry<>(nameAndValue[0], "true");
    }
  }

  private static ConfigItem.Int hiddenIntItem(String name, int defaultValue) {
    ConfigItem.Int i =
        new ConfigItem.Int(NAMESPACE_ROOT, Collections.singletonList(name), defaultValue);
    knownOptions.add(i);
    return i;
  }

  private static ConfigItem.Str strItem(String name, String defaultValue, String description) {
    ConfigItem.Str i = new ConfigItem.Str(
        NAMESPACE_ROOT, Collections.singletonList(name), defaultValue, description, false);
    knownOptions.add(i);
    return i;
  }

  private static ConfigItem.Str hiddenStrItem(String name, String defaultValue) {
    ConfigItem.Str i =
        new ConfigItem.Str(NAMESPACE_ROOT, Collections.singletonList(name), defaultValue);
    knownOptions.add(i);
    return i;
  }

  private static ConfigItem.Bool boolItem(String name, boolean defaultValue, String description) {
    return boolItem(Collections.singletonList(name), defaultValue, description);
  }

  private static ConfigItem.Bool boolItem(
      List<String> nameSegments, boolean defaultValue, String description) {
    ConfigItem.Bool i =
        new ConfigItem.Bool(NAMESPACE_ROOT, nameSegments, defaultValue, description, false);
    knownOptions.add(i);
    return i;
  }

  private static ConfigItem.Bool hiddenBoolItem(String name, boolean defaultValue) {
    ConfigItem.Bool i =
        new ConfigItem.Bool(NAMESPACE_ROOT, Collections.singletonList(name), defaultValue);
    knownOptions.add(i);
    return i;
  }

  private static ConfigItem.StrList strListItem(String name, char delimiter, String description) {
    ConfigItem.StrList i = new ConfigItem.StrList(
        NAMESPACE_ROOT, Collections.singletonList(name), delimiter, description, false);
    knownOptions.add(i);
    return i;
  }

  private static ConfigItem.StrList hiddenStrListItem(String name, char delimiter) {
    ConfigItem.StrList i =
        new ConfigItem.StrList(NAMESPACE_ROOT, Collections.singletonList(name), delimiter);
    knownOptions.add(i);
    return i;
  }

  private static ConfigItem.HexSet hexSetItem(String name, char delimiter, String description) {
    ConfigItem.HexSet i = new ConfigItem.HexSet(
        NAMESPACE_ROOT, Collections.singletonList(name), delimiter, description, false);
    knownOptions.add(i);
    return i;
  }

  private static ConfigItem.Uint64 uint64Item(String name, Long defaultValue, String description) {
    ConfigItem.Uint64 i = new ConfigItem.Uint64(
        NAMESPACE_ROOT, Collections.singletonList(name), defaultValue, description, false);
    knownOptions.add(i);
    return i;
  }

  private static ConfigItem.Uint64 uint64Item(String name, int defaultValue, String description) {
    ConfigItem.Uint64 i = new ConfigItem.Uint64(
        NAMESPACE_ROOT, Collections.singletonList(name), (long) defaultValue, description, false);
    knownOptions.add(i);
    return i;
  }
}
