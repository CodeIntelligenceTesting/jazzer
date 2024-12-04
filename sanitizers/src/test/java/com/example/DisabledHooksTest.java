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

package com.example;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.util.Base64;
import org.junit.After;
import org.junit.Test;

public class DisabledHooksTest {
  public static void triggerReflectiveCallSanitizer() {
    try {
      Class.forName("jaz.Zer").newInstance();
    } catch (ClassNotFoundException | IllegalAccessException | InstantiationException ignored) {
    }
  }

  public static void triggerExpressionLanguageInjectionSanitizer() throws Throwable {
    try {
      Class.forName("jaz.Zer").getMethod("el").invoke(null);
    } catch (InvocationTargetException e) {
      throw e.getCause();
    } catch (IllegalAccessException | ClassNotFoundException | NoSuchMethodException ignore) {
    }
  }

  public static void triggerDeserializationSanitizer() {
    byte[] data =
        Base64.getDecoder().decode("rO0ABXNyAAdqYXouWmVyAAAAAAAAACoCAAFCAAlzYW5pdGl6ZXJ4cAEK");
    try {
      ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
      System.out.println(ois.readObject());
    } catch (IOException | ClassNotFoundException ignore) {
    }
  }

  @After
  public void resetDisabledHooksProperty() {
    System.clearProperty("jazzer.disabled_hooks");
  }

  @Test(expected = FuzzerSecurityIssueHigh.class)
  public void enableReflectiveCallSanitizer() {
    triggerReflectiveCallSanitizer();
  }

  @Test(expected = FuzzerSecurityIssueHigh.class)
  public void enableDeserializationSanitizer() {
    triggerDeserializationSanitizer();
  }

  @Test(expected = FuzzerSecurityIssueHigh.class)
  public void enableExpressionLanguageInjectionSanitizer() throws Throwable {
    triggerExpressionLanguageInjectionSanitizer();
  }

  @Test
  public void disableReflectiveCallSanitizer() {
    System.setProperty(
        "jazzer.disabled_hooks", "com.code_intelligence.jazzer.sanitizers.ReflectiveCall");
    triggerReflectiveCallSanitizer();
  }

  @Test
  public void disableDeserializationSanitizer() {
    System.setProperty(
        "jazzer.disabled_hooks", "com.code_intelligence.jazzer.sanitizers.Deserialization");
    triggerDeserializationSanitizer();
  }

  @Test
  public void disableExpressionLanguageSanitizer() throws Throwable {
    System.setProperty(
        "jazzer.disabled_hooks",
        "com.code_intelligence.jazzer.sanitizers.ExpressionLanguageInjection");
    triggerExpressionLanguageInjectionSanitizer();
  }

  @Test(expected = FuzzerSecurityIssueHigh.class)
  public void disableReflectiveCallAndEnableDeserialization() {
    System.setProperty(
        "jazzer.disabled_hooks", "com.code_intelligence.jazzer.sanitizers.ReflectiveCall");
    triggerReflectiveCallSanitizer();
    triggerDeserializationSanitizer();
  }

  @Test
  public void disableAllSanitizers() throws Throwable {
    System.setProperty(
        "jazzer.disabled_hooks",
        "com.code_intelligence.jazzer.sanitizers.ReflectiveCall,"
            + "com.code_intelligence.jazzer.sanitizers.Deserialization,"
            + "com.code_intelligence.jazzer.sanitizers.ExpressionLanguageInjection");
    triggerReflectiveCallSanitizer();
    triggerExpressionLanguageInjectionSanitizer();
    triggerDeserializationSanitizer();
  }
}
