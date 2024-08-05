/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.autofuzz;

import static com.code_intelligence.jazzer.autofuzz.AutofuzzCodegenVisitor.escapeForLiteral;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class AutofuzzCodegenVisitorTest {
  @Test
  public void escapeForLiteralTest() {
    assertEquals("\\t", escapeForLiteral("\t"));
    assertEquals("\\\\\\t", escapeForLiteral("\\\t"));
    assertEquals("\\b", escapeForLiteral("\b"));
    assertEquals("\\\\\\b", escapeForLiteral("\\\b"));
    assertEquals("\\n", escapeForLiteral("\n"));
    assertEquals("\\\\\\n", escapeForLiteral("\\\n"));
    assertEquals("\\r", escapeForLiteral("\r"));
    assertEquals("\\\\\\r", escapeForLiteral("\\\r"));
    assertEquals("\\f", escapeForLiteral("\f"));
    assertEquals("\\\\\\f", escapeForLiteral("\\\f"));
    assertEquals("\\'", escapeForLiteral("'"));
    assertEquals("\\\\\\'", escapeForLiteral("\\'"));
    assertEquals("\\\"", escapeForLiteral("\""));
    assertEquals("\\\\\\\"", escapeForLiteral("\\\""));
    assertEquals("\\\\", escapeForLiteral("\\"));
  }
}
