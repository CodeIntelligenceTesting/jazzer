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
