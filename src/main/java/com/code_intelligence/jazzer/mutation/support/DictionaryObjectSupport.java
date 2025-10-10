/*
 * Copyright 2025 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.mutation.support;

import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;

import com.code_intelligence.jazzer.mutation.annotation.DictionaryObject;
import java.lang.reflect.AnnotatedType;
import java.util.Arrays;

public class DictionaryObjectSupport {

  /**
   * Extract inverse probability of the very last {@code DictionaryObject} annotation on the given
   * type.
   */
  public static int extractLastInvProbability(AnnotatedType type) {
    DictionaryObject[] dictObj = type.getAnnotationsByType(DictionaryObject.class);
    int pInv =
        Arrays.stream(dictObj)
            .map(DictionaryObject::pInv)
            .reduce((first, second) -> second)
            .orElseThrow(() -> new IllegalStateException("No DictionaryObject annotation found"));
    require(pInv >= 2, "@DictionaryObject.pInv must be at least 2");
    return pInv;
  }
}
