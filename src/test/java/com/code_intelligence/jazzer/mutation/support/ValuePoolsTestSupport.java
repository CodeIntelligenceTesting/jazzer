/*
 * Copyright 2026 Code Intelligence GmbH
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

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

public class ValuePoolsTestSupport {

  public static Stream<?> myPool() {
    return Stream.of("external1", "external2", "external3", 1232187321, -182371);
  }

  private static Stream<?> myPrivatePoolWithOverload() {
    return Stream.of("external1", "external2", "external3", 1232187321, -182371);
  }

  private static Stream<?> myPrivatePoolWithOverload(int ignored) {
    return Stream.of("should not be used");
  }

  public static final class Nested {
    public static Stream<?> myPool() {
      return Stream.of("nested");
    }
  }

  private static List<Integer> listSupplier() {
    return Arrays.asList(1, 2, 3);
  }
}
