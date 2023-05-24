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

import static java.util.Collections.emptySet;
import static java.util.Collections.unmodifiableSet;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Defines a configuration item which holds its value in Java's system properties to ensure that
 * multiple references use the same value. If a matching key already exists, the value will not be
 * overwritten with
 * {@code defaultValue} but will be overwritten if {@code set} or {@code setRawValue} is called.
 * @param <T>
 */
public abstract class ConfigItem<T> {
  private final String namespace;
  private final List<String> nameSegments;
  final String defaultValue;
  final String description;
  final boolean hidden;
  /**
   * This tracks if a has been explicitly set rather than having its default value. Used for
   * handling invariants between config items
   */
  private boolean set;

  ConfigItem(String rootNamespace, List<String> nameSegments, String rawDefaultValue,
      String description, boolean hidden) {
    this.namespace = rootNamespace;
    this.nameSegments = nameSegments;
    this.defaultValue = rawDefaultValue;
    this.description = description;
    this.hidden = hidden;
    this.set = false;

    String propName = getPropertyName();
    String value = System.getProperty(propName);
    // only set the value if it wasn't there already
    if (value == null) {
      System.setProperty(propName, rawDefaultValue);
    }
  }

  ConfigItem(String rootNamespace, List<String> nameSegments, String rawDefaultValue) {
    this(rootNamespace, nameSegments, rawDefaultValue, "", true);
  }

  Optional<String> description() {
    if (hidden) {
      return Optional.empty();
    } else {
      return Optional.of(String.format("%s (default: %s)", description, defaultValue));
    }
  }

  String getRawValue() {
    return System.getProperty(getPropertyName());
  }

  protected void setRawValue(String value) {
    set = true;
    System.setProperty(getPropertyName(), value);
  }

  protected String getPropertyName() {
    return Stream.concat(Stream.of(namespace), nameSegments.stream())
        .map(segment -> segment.toLowerCase(Locale.ROOT))
        .collect(Collectors.joining("."));
  }

  public String getEnvName() {
    return Stream.concat(Stream.of(namespace), nameSegments.stream())
        .map(segment -> segment.toUpperCase(Locale.ROOT))
        .collect(Collectors.joining("_"));
  }

  public String getManifestName() {
    return Stream.concat(Stream.of(namespace), nameSegments.stream())
        .map(segment -> segment.toLowerCase(Locale.ROOT))
        .collect(Collectors.joining("_"));
  }

  /**
   * Unlike the other possible names for config items, we don't want to type the namespace in each
   * CLI flag
   * @return
   */
  public String getCliArgName() {
    return nameSegments.stream()
        .map(segment -> segment.toLowerCase(Locale.ROOT))
        .collect(Collectors.joining("-"));
  }

  public T get() {
    String raw = getRawValue();
    return parse(raw);
  }

  boolean isSet() {
    return set;
  }

  public void reset() {
    System.setProperty(getPropertyName(), defaultValue);
  }

  public abstract void set(T value);

  protected abstract T parse(String value);

  final void setFromString(String value) {
    set(parse(value));
  }

  public static class Int extends ConfigItem<Integer> {
    public Int(String namespace, List<String> segments, Integer defaultValue) {
      super(namespace, segments, defaultValue.toString());
    }

    public Int(String namespace, List<String> segments, Integer defaultValue, String description,
        boolean hidden) {
      super(namespace, segments, defaultValue.toString(), description, hidden);
    }

    @Override
    public void set(Integer value) {
      super.setRawValue(value.toString());
    }

    @Override
    protected Integer parse(String value) {
      return Integer.valueOf(value);
    }
  }

  public static class Str extends ConfigItem<String> {
    public Str(String namespace, List<String> segments, String defaultValue) {
      super(namespace, segments, defaultValue);
    }

    public Str(String namespace, List<String> segments, String defaultValue, String description,
        boolean hidden) {
      super(namespace, segments, defaultValue, description, hidden);
    }

    @Override
    public void set(String value) {
      // System.out.printf("SETTING %s to %s%n", getPropertyName(), value);
      this.setRawValue(value);
    }

    @Override
    protected String parse(String value) {
      return value;
    }
  }

  public static class Bool extends ConfigItem<Boolean> {
    public Bool(String namespace, List<String> segments, boolean defaultValue) {
      super(namespace, segments, Boolean.toString(defaultValue));
    }

    public Bool(String namespace, List<String> segments, boolean defaultValue, String description,
        boolean hidden) {
      super(namespace, segments, Boolean.toString(defaultValue), description, hidden);
    }

    @Override
    public void set(Boolean value) {
      String raw = value.toString();
      this.setRawValue(raw);
    }

    @Override
    protected Boolean parse(String value) {
      return Boolean.parseBoolean(value);
    }
  }

  public static class StrList extends ConfigItem<List<String>> {
    final String delimiter;

    public StrList(String namespace, List<String> segments, char delimiter) {
      super(namespace, segments, "");
      this.delimiter = String.valueOf(delimiter);
    }

    public StrList(String namespace, List<String> segments, char delimiter, String description,
        boolean hidden) {
      super(namespace, segments, "", description, hidden);
      this.delimiter = String.valueOf(delimiter);
    }

    @Override
    public void set(List<String> value) {
      String raw = String.join(delimiter, value);
      setRawValue(raw);
    }

    @Override
    protected List<String> parse(String value) {
      if (value.isEmpty()) {
        return new ArrayList<>();
      }
      String[] parts = value.split(delimiter);
      return Stream.of(parts).collect(Collectors.toList());
    }
  }

  public static class HexSet extends ConfigItem<Set<Long>> {
    final String delimiter;

    public HexSet(String namespace, List<String> segments, char delimiter) {
      super(namespace, segments, "");
      this.delimiter = String.valueOf(delimiter);
    }

    public HexSet(String namespace, List<String> segments, char delimiter, String description,
        boolean hidden) {
      super(namespace, segments, "", description, hidden);
      this.delimiter = String.valueOf(delimiter);
    }

    @Override
    public void set(Set<Long> value) {
      String raw = value.stream().map(Long::toHexString).collect(Collectors.joining(delimiter));
      setRawValue(raw);
    }

    @Override
    protected Set<Long> parse(String value) {
      if (value.isEmpty()) {
        return emptySet();
      }
      String[] parts = value.split(delimiter);
      return unmodifiableSet(Stream.of(parts)
                                 .map(token -> Long.parseUnsignedLong(token, 16))
                                 .collect(Collectors.toSet()));
    }
  }

  public static class Uint64 extends ConfigItem<Long> {
    public Uint64(String namespace, List<String> segments, Long defaultValue) {
      super(namespace, segments, Long.toUnsignedString(defaultValue, 10));
    }

    public Uint64(String namespace, List<String> segments, Long defaultValue, String description,
        boolean hidden) {
      super(namespace, segments, Long.toUnsignedString(defaultValue, 10), description, hidden);
    }

    @Override
    public void set(Long value) {
      String raw = Long.toUnsignedString(value, 10);
      setRawValue(raw);
    }

    @Override
    protected Long parse(String value) {
      return Long.parseUnsignedLong(value, 10);
    }
  }
}
