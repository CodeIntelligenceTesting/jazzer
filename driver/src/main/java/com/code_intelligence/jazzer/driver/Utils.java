/*
 * Copyright 2022 Code Intelligence GmbH
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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class Utils {
  /**
   * Convert the arguments to UTF8 before passing them on to JNI as there are no JNI functions to
   * get (unmodified) UTF-8 out of a jstring.
   */
  static byte[][] toNativeArgs(Collection<String> args) {
    return args.stream().map(str -> str.getBytes(StandardCharsets.UTF_8)).toArray(byte[][] ::new);
  }

  static List<String> fromNativeArgs(byte[][] args) {
    return Arrays.stream(args)
        .map(bytes -> new String(bytes, StandardCharsets.UTF_8))
        .collect(Collectors.toList());
  }
}
