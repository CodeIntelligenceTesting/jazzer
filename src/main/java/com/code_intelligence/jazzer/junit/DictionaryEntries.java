/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.junit;

import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Adds the given strings to the fuzzer's dictionary. This is particularly useful for adding strings
 * that have special meaning in the context of your fuzz test, but are difficult for the fuzzer to
 * discover automatically.
 *
 * <p>Typical examples include valid credentials for mock accounts in a web application or a
 * collection of valid HTML tags for an HTML parser.
 */
@Target({ElementType.METHOD, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Repeatable(DictionaryEntriesList.class)
public @interface DictionaryEntries {
  /** Individual strings to add to the fuzzer dictionary. */
  String[] value();
}
