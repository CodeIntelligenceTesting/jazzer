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

import static com.google.common.truth.Truth.assertThat;
import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.code_intelligence.jazzer.driver.OptItem.StrList;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class OptItemTest {
  private static OptItem<List<String>> testOptItem(String name) {
    return new StrList(name, "some description", ',', true);
  }

  @BeforeAll
  static void setAdditionalSources() {
    Map<String, String> configurationParams = new HashMap<>();
    configurationParams.put("jazzer.some_arg", "config_1,config_2");
    configurationParams.put("jazzer.other_arg", "config_3,config_4");
    OptItem.registerConfigurationParameters(
        key -> Optional.ofNullable(configurationParams.get(key)));

    List<Map.Entry<String, String>> cliArgs = new ArrayList<>();
    cliArgs.add(new SimpleEntry<>("some_arg", "cli_1,cli_2"));
    cliArgs.add(new SimpleEntry<>("other_arg", "cli_3"));
    cliArgs.add(new SimpleEntry<>("other_arg", "cli_4,cli_5"));
    cliArgs.add(new SimpleEntry<>("some_arg", "cli_6"));
    OptItem.registerCommandLineArgs(cliArgs);
    // Verify that the list contents have been copied.
    cliArgs.get(0).setValue("not_cli_1");
    cliArgs.clear();

    System.setProperty("jazzer.some_arg", "property_1,property_2");
    System.setProperty("jazzer.other_arg", "property_3,property_4");
  }

  @Test
  void optItem_precedence() {
    // See BUILD.bazel for environment variables and manifest entries.
    assertThat(testOptItem("some_arg").get())
        .containsExactly(
            "manifest_3",
            "manifest_4",
            "manifest_5",
            "manifest_7",
            "env_1",
            "env_2",
            "property_1",
            "property_2",
            "config_1",
            "config_2",
            "cli_1",
            "cli_2",
            "cli_6")
        .inOrder();
    assertThat(testOptItem("other_arg").get())
        .containsExactly(
            "manifest_1",
            "manifest_2",
            "manifest_6",
            "env_3",
            "property_3",
            "property_4",
            "config_3",
            "config_4",
            "cli_3",
            "cli_4",
            "cli_5")
        .inOrder();
  }

  @Test
  void optItem_default() {
    assertThat(testOptItem("unset_arg").get()).isEmpty();
  }

  @Test
  void optItem_setIfDefault() {
    OptItem<List<String>> unsetArg = testOptItem("unset_arg");
    assertThat(unsetArg.setIfDefault(Arrays.asList("not", "default"))).isTrue();
    assertThat(unsetArg.get()).containsExactly("not", "default").inOrder();
    assertThrows(
        IllegalStateException.class,
        () -> unsetArg.setIfDefault(Arrays.asList("also", "not", "default")));
  }

  @Test
  void optItem_setIfDefault_ignored() {
    OptItem<List<String>> setArg = testOptItem("some_arg");
    assertThat(setArg.setIfDefault(singletonList("not_default"))).isFalse();
    assertThat(setArg.get()).doesNotContain("not_default");
    assertThrows(
        IllegalStateException.class,
        () -> setArg.setIfDefault(Arrays.asList("also", "not", "default")));
  }

  @Test
  void optItem_boolean() {
    OptItem<Boolean> booleanArg = new OptItem.Bool("valid_boolean", "some description", "foo");
    assertThat(booleanArg.get()).isTrue();
  }

  @Test
  void optItem_boolean_invalid() {
    OptItem<Boolean> booleanArg = new OptItem.Bool("invalid_boolean", "some description", "foo");
    assertThat(assertThrows(OptItem.IllegalOptionValueException.class, booleanArg::get))
        .hasMessageThat()
        .isEqualTo("Invalid value for boolean option invalid_boolean: not_true");
  }

  @Test
  void splitString() {
    assertStringSplit("", ',');
    assertStringSplit(",,,,,", ',');
    assertStringSplit("fir\\\\st se\\ cond      third", ' ', "fir\\st", "se cond", "third");
    assertStringSplit("first ", ' ', "first");
    assertStringSplit("first\\", ' ', "first");
  }

  @Test
  void splitString_noBackslashAsSeparator() {
    assertThrows(IllegalArgumentException.class, () -> assertStringSplit("foo", '\\'));
  }

  public void assertStringSplit(String str, char sep, String... tokens) {
    assertThat(OptItem.StrList.splitOnUnescapedSeparator(str, sep))
        .containsExactlyElementsIn(tokens)
        .inOrder();
  }
}
