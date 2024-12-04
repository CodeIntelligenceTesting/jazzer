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

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.list;
import static java.util.Collections.reverse;
import static java.util.Collections.unmodifiableList;
import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toList;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URL;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.jar.Manifest;
import java.util.stream.Stream;

/** A typed option that is evaluated lazily (see {@link #get()}). */
@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
public abstract class OptItem<T> implements Supplier<T> {
  private static final String ROOT_SEGMENT = "jazzer";
  private static final String INTERNAL_SEGMENT = "internal";

  private static Optional<List<Map.Entry<String, String>>> cliArgs = Optional.empty();
  private static Optional<Function<String, Optional<String>>> configurationParameterGetter =
      Optional.empty();

  private final String name;
  private final String rawDefaultValue;
  private final String description;

  private T value;

  protected OptItem(String name, String defaultValue, String description) {
    this.name = requireNonNull(name);
    this.rawDefaultValue = requireNonNull(defaultValue);
    this.description = description;
  }

  /**
   * Adds the given command-line arguments as a value source for items.
   *
   * <p>Must only be called once.
   */
  static void registerCommandLineArgs(List<Map.Entry<String, String>> cliArgs) {
    if (OptItem.cliArgs.isPresent()) {
      throw new IllegalStateException("Command-line arguments have already been set");
    }
    OptItem.cliArgs =
        Optional.of(
            unmodifiableList(
                cliArgs.stream()
                    .map(e -> new SimpleImmutableEntry<>(e.getKey(), e.getValue()))
                    .collect(toList())));
  }

  /**
   * Adds the JUnit configuration parameters as a value source for items.
   *
   * <p>Must only be called once.
   */
  static void registerConfigurationParameters(
      Function<String, Optional<String>> configurationParameterGetter) {
    if (OptItem.configurationParameterGetter.isPresent()) {
      throw new IllegalStateException("Configuration parameters have already been set");
    }
    OptItem.configurationParameterGetter = Optional.of(configurationParameterGetter);
  }

  /**
   * Get the value of this item, which is cached on the first call of this method and will not
   * change afterward.
   *
   * <p>The value of an item {@code some_opt} is obtained from the following sources in increasing
   * order of precedence:
   *
   * <ol>
   *   <li>the default value;
   *   <li>{@code META-INF/MANIFEST.MF} attributes {@code Jazzer-Some-Opt} on the classpath;
   *   <li>the {@code JAZZER_SOME_OPT} environment variable;
   *   <li>the {@code jazzer.some_opt} system property;
   *   <li>the {@code jazzer.some_opt} JUnit configuration parameter (if {@link
   *       #registerConfigurationParameters(Function)} has been called);
   *   <li>the {@code --some_opt} command-line argument (if {@link #registerCommandLineArgs(List)
   *       has been called}).
   * </ol>
   */
  @Override
  public final T get() throws IllegalOptionValueException {
    // Benign data race since we only ever read value once.
    T localValue = value;
    if (localValue == null) {
      localValue =
          getExplicitValue().orElseGet(() -> fromStringOrThrow(rawDefaultValue, "default"));
      value = localValue;
    }
    return localValue;
  }

  /**
   * If {@link #get()} hasn't been called yet, locks in the value of this item with {@code newValue}
   * taking the role of its default value, otherwise throws an {@link IllegalStateException}.
   *
   * @return {@code true} if the value of the item was not set explicitly and thus defaulted to
   *     {@code newValue}.
   */
  public final boolean setIfDefault(T newValue) throws IllegalOptionValueException {
    if (value != null) {
      throw new IllegalStateException(
          String.format(
              "Attempted to set of option %s to %s, but it has already been read elsewhere",
              propertyName(), newValue));
    }
    Optional<T> explicitValue = getExplicitValue();
    if (explicitValue.isPresent()) {
      value = explicitValue.get();
      return false;
    } else {
      value = newValue;
      return true;
    }
  }

  /**
   * Checks if the given option was set externally via one of the provided methods, e.g. via
   * environment variable or command line parameter.
   *
   * @return true if set via a parameter, else false
   */
  public boolean isSet() {
    return getExplicitValue().isPresent();
  }

  final boolean isInternal() {
    return description == null;
  }

  @Override
  public final String toString() {
    return String.format(
        "--%s (%s, default: \"%s\")%n     %s", name, getType(), rawDefaultValue, description);
  }

  protected abstract Optional<T> fromString(String rawValue);

  protected abstract String getType();

  protected T accumulate(T oldValue, T newValue) {
    return newValue;
  }

  private Optional<T> getExplicitValue() {
    return Stream.<Supplier<Stream<T>>>of(
            this::getFromManifest,
            this::getFromEnv,
            this::getFromProperties,
            this::getFromConfigurationParameters,
            this::getFromCommandLineArguments)
        .flatMap(Supplier::get)
        .reduce(this::accumulate);
  }

  private Stream<T> getFromCommandLineArguments() {
    return cliArgs.orElse(emptyList()).stream()
        .filter(e -> e.getKey().equals(cliArgName()))
        .map(Entry::getValue)
        .map(s -> fromStringOrThrow(s, "command-line argument " + cliArgName()));
  }

  private Stream<T> getFromConfigurationParameters() {
    return stream(configurationParameterGetter.flatMap(getter -> getter.apply(propertyName())))
        .map(s -> fromStringOrThrow(s, "configuration parameter " + propertyName()));
  }

  private Stream<T> getFromProperties() {
    return stream(Optional.ofNullable(System.getProperty(propertyName(), null)))
        .map(s -> fromStringOrThrow(s, "property " + propertyName()));
  }

  private Stream<T> getFromEnv() {
    return stream(Optional.ofNullable(System.getenv(envVariableName())))
        .map(s -> fromStringOrThrow(s, "environment variable " + envVariableName()));
  }

  private Stream<T> getFromManifest() {
    try {
      ArrayList<URL> manifests =
          list(OptItem.class.getClassLoader().getResources("META-INF/MANIFEST.MF"));
      // The manifest entry that comes *last* on the class path should be evaluated *first* as it
      // has the *lowest* precedence.
      reverse(manifests);
      return manifests.stream()
          .flatMap(
              url -> {
                try (InputStream inputStream = url.openStream()) {
                  return stream(
                          Optional.ofNullable(
                              new Manifest(inputStream)
                                  .getMainAttributes()
                                  .getValue(manifestAttributeName())))
                      .map(
                          s ->
                              fromStringOrThrow(
                                  s,
                                  String.format(
                                      "manifest attribute %s in %s",
                                      manifestAttributeName(), url)));
                } catch (IOException e) {
                  throw new UncheckedIOException(e);
                }
              });
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private T fromStringOrThrow(String rawValue, String what) throws IllegalOptionValueException {
    return fromString(rawValue)
        .orElseThrow(
            () ->
                new IllegalOptionValueException(
                    String.format("Invalid value for %s: %s", what, rawValue)));
  }

  String cliArgName() {
    return name;
  }

  private String propertyName() {
    return segments().map(s -> s.toLowerCase(Locale.ROOT)).collect(joining("."));
  }

  private String envVariableName() {
    return segments().map(s -> s.toUpperCase(Locale.ROOT)).collect(joining("_"));
  }

  private String manifestAttributeName() {
    // Manifest attribute names are case-insensitive, so we do not have to emit title case even
    // though that's how these names are usually formatted.
    return segments().map(s -> s.toLowerCase(Locale.ROOT)).collect(joining("_")).replace('_', '-');
  }

  private Stream<String> segments() {
    Stream.Builder<String> builder = Stream.<String>builder().add(ROOT_SEGMENT);
    if (isInternal()) {
      builder.add(INTERNAL_SEGMENT);
    }
    builder.add(name);
    return builder.build();
  }

  public static class IllegalOptionValueException extends IllegalArgumentException {
    protected IllegalOptionValueException(String message) {
      super(message);
    }
  }

  public static final class Bool extends OptItem<Boolean> {
    private static final List<String> TRUE_VALUES =
        unmodifiableList(asList("true", "on", "yes", "y", "1"));
    private static final List<String> FALSE_VALUES =
        unmodifiableList(asList("false", "off", "no", "n", "0"));

    Bool(String name, String defaultValue, String description) {
      super(name, defaultValue, description);
    }

    @Override
    protected Optional<Boolean> fromString(String rawValue) throws IllegalOptionValueException {
      if (TRUE_VALUES.stream().anyMatch(v -> v.equalsIgnoreCase(rawValue))) {
        return Optional.of(true);
      } else if (FALSE_VALUES.stream().anyMatch(v -> v.equalsIgnoreCase(rawValue))) {
        return Optional.of(false);
      } else {
        throw new IllegalOptionValueException(
            String.format("Invalid value for boolean option %s: %s", cliArgName(), rawValue));
      }
    }

    @Override
    protected String getType() {
      return "bool";
    }
  }

  public static final class Uint64 extends OptItem<Long> {
    Uint64(String name, String defaultValue, String description) {
      super(name, defaultValue, description);
    }

    @Override
    protected Optional<Long> fromString(String rawValue) {
      try {
        return Optional.of(Long.parseUnsignedLong(rawValue));
      } catch (NumberFormatException e) {
        return Optional.empty();
      }
    }

    @Override
    protected String getType() {
      return "uint64";
    }
  }

  public static final class Str extends OptItem<String> {
    Str(String name, String defaultValue, String description) {
      super(name, defaultValue, description);
    }

    @Override
    protected Optional<String> fromString(String rawValue) throws IllegalOptionValueException {
      return Optional.of(rawValue);
    }

    @Override
    protected String getType() {
      return "string";
    }
  }

  public static final class StrList extends OptItem<List<String>> {
    private final char separator;
    private final boolean accumulate;

    StrList(String name, String description, char separator, boolean accumulate) {
      super(name, "", description);
      this.separator = separator;
      this.accumulate = accumulate;
    }

    @Override
    protected List<String> accumulate(List<String> oldValue, List<String> newValue) {
      if (accumulate) {
        return unmodifiableList(
            Stream.concat(oldValue.stream(), newValue.stream()).collect(toList()));
      } else {
        return super.accumulate(oldValue, newValue);
      }
    }

    @Override
    protected Optional<List<String>> fromString(String rawValue) {
      return Optional.of(splitOnUnescapedSeparator(rawValue, separator));
    }

    @Override
    protected String getType() {
      return String.format("list separated by '%s'", separator);
    }

    /**
     * Split value into non-empty tokens separated by separator. Backslashes can be used to escape
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
      return unmodifiableList(tokens);
    }
  }

  private static <T> Stream<T> stream(Optional<T> optional) {
    return optional.map(Stream::of).orElseGet(Stream::empty);
  }
}
