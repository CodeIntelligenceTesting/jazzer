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
