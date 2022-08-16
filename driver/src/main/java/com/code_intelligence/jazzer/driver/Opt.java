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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
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
  private static final char SYSTEM_DELIMITER =
      System.getProperty("os.name").startsWith("Windows") ? ';' : ':';

  public static final String autofuzz = stringSetting("autofuzz", "");
  public static final List<String> autofuzzIgnore = stringListSetting("autofuzz_ignore", ',');
  public static final String coverageDump = stringSetting("coverage_dump", "");
  public static final String coverageReport = stringSetting("coverage_report", "");
  public static final List<String> customHookIncludes = stringListSetting("custom_hook_includes");
  public static final List<String> customHookExcludes = stringListSetting("custom_hook_excludes");
  public static final List<String> customHooks = stringListSetting("custom_hooks");
  public static final List<String> disabledHooks = stringListSetting("disabled_hooks");
  public static final String dumpClassesDir = stringSetting("dump_classes_dir", "");
  public static final boolean hooks = boolSetting("hooks", true);
  public static final String idSyncFile = stringSetting("id_sync_file", null);
  public static final List<String> instrumentationIncludes =
      stringListSetting("instrumentation_includes");
  public static final List<String> instrumentationExcludes =
      stringListSetting("instrumentation_excludes");
  public static final Set<Long> ignore =
      Collections.unmodifiableSet(stringListSetting("ignore", ',')
                                      .stream()
                                      .map(Long::parseUnsignedLong)
                                      .collect(Collectors.toSet()));
  public static final String reproducerPath = stringSetting("reproducer_path", ".");
  public static final String targetClass = stringSetting("target_class", "");
  public static final List<String> trace = stringListSetting("trace");

  // The values of these settings depend on autofuzz.
  public static final List<String> targetArgs = autofuzz.isEmpty()
      ? stringListSetting("target_args", ' ')
      : Collections.unmodifiableList(
          Stream.concat(Stream.of(autofuzz), autofuzzIgnore.stream()).collect(Collectors.toList()));
  public static final long keepGoing =
      uint64Setting("keep_going", autofuzz.isEmpty() ? 1 : Long.MAX_VALUE);

  // Default to false if hooks is false to mimic the original behavior of the native fuzz target
  // runner, but still support hooks = false && dedup = true.
  public static final boolean dedup = boolSetting("dedup", hooks);

  static {
    if (!targetClass.isEmpty() && !autofuzz.isEmpty()) {
      err.println("--target_class and --autofuzz cannot be specified together");
      exit(1);
    }
    if (!stringListSetting("target_args", ' ').isEmpty() && !autofuzz.isEmpty()) {
      err.println("--target_args and --autofuzz cannot be specified together");
      exit(1);
    }
    if (autofuzz.isEmpty() && !autofuzzIgnore.isEmpty()) {
      err.println("--autofuzz_ignore requires --autofuzz");
      exit(1);
    }
    if ((!ignore.isEmpty() || keepGoing > 1) && !dedup) {
      // --autofuzz implicitly sets keepGoing to Integer.MAX_VALUE.
      err.println("--nodedup is not supported with --ignore, --keep_going, or --autofuzz");
      exit(1);
    }
  }

  private static final String optionsPrefix = "jazzer.";

  private static String stringSetting(String name, String defaultValue) {
    return System.getProperty(optionsPrefix + name, defaultValue);
  }

  private static List<String> stringListSetting(String name) {
    return stringListSetting(name, SYSTEM_DELIMITER);
  }

  private static List<String> stringListSetting(String name, char separator) {
    String value = System.getProperty(optionsPrefix + name);
    if (value == null || value.isEmpty()) {
      return Collections.emptyList();
    }
    return splitOnUnescapedSeparator(value, separator);
  }

  private static boolean boolSetting(String name, boolean defaultValue) {
    String value = System.getProperty(optionsPrefix + name);
    if (value == null) {
      return defaultValue;
    }
    return Boolean.parseBoolean(value);
  }

  private static long uint64Setting(String name, long defaultValue) {
    String value = System.getProperty(optionsPrefix + name);
    if (value == null) {
      return defaultValue;
    }
    return Long.parseUnsignedLong(value, 10);
  }

  /**
   * Split value into non-empty takens separated by separator. Backslashes can be used to escape
   * separators (or backslashes).
   *
   * @param value the string to split
   * @param separator a single character to split on (backslash is not allowed)
   * @return an immutable list of tokens obtained by splitting value on separator
   */
  static List<String> splitOnUnescapedSeparator(String value, char separator) {
    if (separator == '\\') {
      throw new IllegalArgumentException("separator '\\' is not supported");
    }
    ArrayList<String> tokens = new ArrayList<>();
    StringBuilder currentToken = new StringBuilder();
    boolean inEscapeState = false;
    for (int pos = 0; pos < value.length(); pos++) {
      char c = value.charAt(pos);
      if (inEscapeState) {
        currentToken.append(c);
        inEscapeState = false;
      } else if (c == '\\') {
        inEscapeState = true;
      } else if (c == separator) {
        // Do not emit empty tokens between consecutive separators.
        if (currentToken.length() > 0) {
          tokens.add(currentToken.toString());
        }
        currentToken.setLength(0);
      } else {
        currentToken.append(c);
      }
    }
    if (currentToken.length() > 0) {
      tokens.add(currentToken.toString());
    }
    return Collections.unmodifiableList(tokens);
  }
}
