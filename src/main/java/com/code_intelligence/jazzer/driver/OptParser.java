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

import static java.lang.System.exit;

import com.code_intelligence.jazzer.utils.Log;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

final class OptParser {
  private static final String[] HELP_HEADER = new String[] {
      "A coverage-guided, in-process fuzzer for the JVM",
      "",
      "Usage:",
      String.format(
          "  java -cp jazzer.jar[%cclasspath_entries] com.code_intelligence.jazzer.Jazzer --target_class=<target class> [args...]",
          File.separatorChar),
      String.format(
          "  java -cp jazzer.jar[%cclasspath_entries] com.code_intelligence.jazzer.Jazzer --autofuzz=<method reference> [args...]",
          File.separatorChar),
      "",
      "In addition to the options listed below, Jazzer also accepts all",
      "libFuzzer options described at:",
      "  https://llvm.org/docs/LibFuzzer.html#options",
      "",
      "Options:",
  };
  private static final String OPTIONS_PREFIX = "jazzer.";

  // All supported arguments are added to this set by the individual *Setting methods.
  private static final Map<String, OptDetails> knownArgs = new TreeMap<>();

  static String getHelpText() {
    return Stream
        .concat(Arrays.stream(HELP_HEADER),
            knownArgs.values().stream().filter(Objects::nonNull).map(OptDetails::toString))
        .collect(Collectors.joining("\n\n"));
  }

  static void ignoreSetting(String name) {
    knownArgs.put(name, null);
  }

  static String stringSetting(String name, String defaultValue, String description) {
    knownArgs.put(name, OptDetails.create(name, "string", defaultValue, description));
    return System.getProperty(OPTIONS_PREFIX + name, defaultValue);
  }

  static List<String> stringListSetting(String name, String description) {
    return lazyStringListSetting(name, description).get();
  }

  static List<String> stringListSetting(String name, char separator, String description) {
    return lazyStringListSetting(name, separator, description).get();
  }

  static Supplier<List<String>> lazyStringListSetting(String name, String description) {
    return lazyStringListSetting(name, File.pathSeparatorChar, description);
  }

  static Supplier<List<String>> lazyStringListSetting(
      String name, char separator, String description) {
    knownArgs.put(name,
        OptDetails.create(
            name, String.format("list separated by '%c'", separator), "", description));
    return () -> {
      String value = System.getProperty(OPTIONS_PREFIX + name);
      if (value == null || value.isEmpty()) {
        return Collections.emptyList();
      }
      return splitOnUnescapedSeparator(value, separator);
    };
  }

  static boolean boolSetting(String name, boolean defaultValue, String description) {
    knownArgs.put(
        name, OptDetails.create(name, "boolean", Boolean.toString(defaultValue), description));
    String value = System.getProperty(OPTIONS_PREFIX + name);
    if (value == null) {
      return defaultValue;
    }
    return Boolean.parseBoolean(value);
  }

  static long uint64Setting(String name, long defaultValue, String description) {
    knownArgs.put(
        name, OptDetails.create(name, "uint64", Long.toUnsignedString(defaultValue), description));
    String value = System.getProperty(OPTIONS_PREFIX + name);
    if (value == null) {
      return defaultValue;
    }
    return Long.parseUnsignedLong(value, 10);
  }

  static void failOnUnknownArgument() {
    System.getProperties()
        .keySet()
        .stream()
        .map(key -> (String) key)
        .filter(key -> key.startsWith("jazzer."))
        .map(key -> key.substring("jazzer.".length()))
        .filter(key -> !key.startsWith("internal."))
        .filter(key -> !knownArgs.containsKey(key))
        .findFirst()
        .ifPresent(unknownArg -> {
          Log.error(String.format(
              "Unknown argument '--%1$s' or property 'jazzer.%1$s' (list all available arguments with --help)",
              unknownArg));
          exit(1);
        });
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

  private static final class OptDetails {
    final String name;
    final String type;
    final String defaultValue;
    final String description;

    private OptDetails(String name, String type, String defaultValue, String description) {
      this.name = name;
      this.type = type;
      this.defaultValue = defaultValue;
      this.description = description;
    }

    static OptDetails create(String name, String type, String defaultValue, String description) {
      if (description == null) {
        return null;
      }
      return new OptDetails(checkNotNullOrEmpty(name, "name"), checkNotNullOrEmpty(type, "type"),
          defaultValue, checkNotNullOrEmpty(description, "description"));
    }

    @Override
    public String toString() {
      return String.format(
          "--%s (%s, default: \"%s\")%n     %s", name, type, defaultValue, description);
    }

    private static String checkNotNullOrEmpty(String arg, String name) {
      if (arg == null) {
        throw new NullPointerException(name + " must not be null");
      }
      if (arg.isEmpty()) {
        throw new NullPointerException(name + " must not be empty");
      }
      return arg;
    }
  }
}
