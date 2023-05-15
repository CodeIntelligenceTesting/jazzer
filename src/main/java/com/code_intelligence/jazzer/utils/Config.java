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

  public static ConfigItem.Str foo = strItem("foo", "baz");

  public static ConfigItem.Int bar = intItem("bar", 10);

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

    System.setProperty("jazzer.config-loaded", "true");
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

  private static ConfigItem.Int intItem(String name, int defaultValue) {
    ConfigItem.Int i =
        new ConfigItem.Int(NAMESPACE_ROOT, Collections.singletonList(name), defaultValue);
    knownOptions.add(i);
    return i;
  }

  private static ConfigItem.Str strItem(String name, String defaultValue) {
    ConfigItem.Str i = new ConfigItem.Str(NAMESPACE_ROOT, Arrays.asList(name), defaultValue);
    knownOptions.add(i);
    return i;
  }

  private static ConfigItem.Bool boolItem(String name, boolean defaultValue) {
    ConfigItem.Bool i = new ConfigItem.Bool(NAMESPACE_ROOT, Arrays.asList(name), defaultValue);
    knownOptions.add(i);
    return i;
  }
}
