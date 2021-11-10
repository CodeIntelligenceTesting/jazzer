// Copyright 2021 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.code_intelligence.jazzer.generated;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class JavaNoThrowMethods {
  private static final String DATA_FILE_NAME = "java_no_throw_methods_list.dat";
  private static final String DATA_FILE_RESOURCE_PATH = String.format(
      "%s/%s", JavaNoThrowMethods.class.getPackage().getName().replace('.', '/'), DATA_FILE_NAME);

  public static final Set<String> LIST = readJavaNoThrowMethods();

  private static Set<String> readJavaNoThrowMethods() {
    // If we successfully appended the agent JAR to the bootstrap class loader path in Agent, the
    // classLoader property of JavaNoThrowMethods returns null and we have to use the system class
    // loader instead.
    ClassLoader classLoader = JavaNoThrowMethods.class.getClassLoader();
    if (classLoader == null) {
      classLoader = ClassLoader.getSystemClassLoader();
    }
    Set<String> list;
    try (InputStream resourceStream = classLoader.getResourceAsStream(DATA_FILE_RESOURCE_PATH)) {
      if (resourceStream == null) {
        System.out.printf("ERROR: No-throw method signatures not found at resource path: %s%n",
            DATA_FILE_RESOURCE_PATH);
        return new HashSet<>();
      }
      try (BufferedReader resourceReader =
               new BufferedReader(new InputStreamReader(resourceStream))) {
        list = resourceReader.lines().collect(Collectors.toSet());
      }
    } catch (IOException e) {
      System.out.println("ERROR: Failed to load no-throw method signatures");
      e.printStackTrace();
      return new HashSet<>();
    }
    System.out.printf("INFO: Loaded %d no-throw method signatures%n", list.size());
    return list;
  }
}
