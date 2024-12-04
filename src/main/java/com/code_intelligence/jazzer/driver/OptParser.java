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

package com.code_intelligence.jazzer.driver;

import static java.lang.System.exit;
import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toSet;

import com.code_intelligence.jazzer.utils.Log;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

final class OptParser {
  private static final String[] HELP_HEADER =
      new String[] {
        "A coverage-guided, in-process fuzzer for the JVM",
        "",
        "Usage:",
        String.format(
            "  java -cp jazzer.jar[%cclasspath_entries] com.code_intelligence.jazzer.Jazzer"
                + " --target_class=<target class> [args...]",
            File.separatorChar),
        String.format(
            "  java -cp jazzer.jar[%cclasspath_entries] com.code_intelligence.jazzer.Jazzer"
                + " --autofuzz=<method reference> [args...]",
            File.separatorChar),
        "",
        "In addition to the options listed below, Jazzer also accepts all",
        "libFuzzer options described at:",
        "  https://llvm.org/docs/LibFuzzer.html#options",
        "",
        "Options:",
      };

  // All supported arguments are added to this set by the individual *Setting methods.
  private static final List<OptItem<?>> knownArgs = new ArrayList<>();

  static String getHelpText() {
    return Stream.concat(
            Arrays.stream(HELP_HEADER),
            knownArgs.stream().filter(Objects::nonNull).map(OptItem::toString))
        .collect(joining("\n\n"));
  }

  static OptItem<String> stringSetting(String name, String defaultValue, String description) {
    OptItem<String> opt = new OptItem.Str(name, defaultValue, description);
    knownArgs.add(opt);
    return opt;
  }

  static OptItem<List<String>> stringListSetting(String name, String description) {
    return stringListSetting(name, File.pathSeparatorChar, description);
  }

  static OptItem<List<String>> stringListSetting(String name, char separator, String description) {
    OptItem<List<String>> opt = new OptItem.StrList(name, description, separator, false);
    knownArgs.add(opt);
    return opt;
  }

  static OptItem<Boolean> boolSetting(String name, boolean defaultValue, String description) {
    OptItem<Boolean> opt = new OptItem.Bool(name, Boolean.toString(defaultValue), description);
    knownArgs.add(opt);
    return opt;
  }

  static OptItem<Long> uint64Setting(String name, long defaultValue, String description) {
    OptItem<Long> opt = new OptItem.Uint64(name, Long.toUnsignedString(defaultValue), description);
    knownArgs.add(opt);
    return opt;
  }

  static void registerAndValidateCommandLineArgs(List<Map.Entry<String, String>> cliArgs) {
    Set<String> allowedArgs =
        knownArgs.stream()
            .filter(optItem -> !optItem.isInternal())
            .map(OptItem::cliArgName)
            .collect(toSet());
    String invalidArgs =
        cliArgs.stream()
            .map(Entry::getKey)
            .filter(arg -> !allowedArgs.contains(arg))
            .distinct()
            .map(arg -> "--" + arg)
            .collect(joining(", "));

    if (!invalidArgs.isEmpty()) {
      Log.error("Unknown arguments (list available arguments with --help): " + invalidArgs);
      exit(1);
    }

    OptItem.registerCommandLineArgs(cliArgs);
  }

  public static void registerConfigurationParameters(
      Function<String, Optional<String>> configurationParameterGetter) {
    OptItem.registerConfigurationParameters(configurationParameterGetter);
  }
}
