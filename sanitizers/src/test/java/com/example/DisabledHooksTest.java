/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
