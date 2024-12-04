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

package com.code_intelligence.jazzer.driver;

import com.code_intelligence.jazzer.agent.AgentInstaller;
import com.code_intelligence.jazzer.utils.Log;
import com.code_intelligence.jazzer.utils.ZipUtils;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.ZipOutputStream;

public class OfflineInstrumentor {
  /**
   * Create a new jar file at <jazzer_path>/<jarBaseName>.instrumented.jar for each jar in passed
   * in, with classes that have Jazzer instrumentation.
   *
   * @param jarLists list of jars to instrument
   * @return a boolean representing the success status
   */
  public static boolean instrumentJars(List<String> jarLists) {
    AgentInstaller.install(Opt.hooks.get());

    // Clear Opt.dumpClassesDir before adding new instrumented classes
    File dumpClassesDir = new File(Opt.dumpClassesDir.get());
    if (dumpClassesDir.exists()) {
      for (String fn : dumpClassesDir.list()) {
        new File(Opt.dumpClassesDir.get(), fn).delete();
      }
    }

    List<String> errorMessages = new ArrayList<>();
    for (String jarPath : jarLists) {
      String outputBaseName = jarPath;
      if (outputBaseName.contains(File.separator)) {
        outputBaseName =
            outputBaseName.substring(
                outputBaseName.lastIndexOf(File.separator) + 1, outputBaseName.length());
      }

      if (outputBaseName.contains(".jar")) {
        outputBaseName = outputBaseName.substring(0, outputBaseName.lastIndexOf(".jar"));
      }

      Log.info("Instrumenting jar file: " + jarPath);

      try {
        errorMessages = createInstrumentedClasses(jarPath);
      } catch (IOException e) {
        errorMessages.add(
            "Failed to instrument jar: "
                + jarPath
                + ". Please ensure the file at this location is a jar file. Error Message: "
                + e);
        continue;
      }

      try {
        createInstrumentedJar(
            jarPath,
            Opt.dumpClassesDir.get() + File.separator + outputBaseName,
            outputBaseName + ".instrumented.jar");
      } catch (Exception e) {
        errorMessages.add("Failed to instrument jar: " + jarPath + ". Error: " + e);
      }
    }

    // Log all errors at the end
    for (String error : errorMessages) {
      Log.error(error);
    }

    return errorMessages.isEmpty();
  }

  /**
   * Loops over all classes in jar file and adds instrumentation. The output of the instrumented
   * classes will be at --dump-classes-dir
   *
   * @param jarPath a path to a jar file to instrument.
   * @return a list of errors that were hit when trying to instrument all classes in jar
   */
  private static List<String> createInstrumentedClasses(String jarPath) throws IOException {
    List<String> errorMessages = new ArrayList<>();
    List<String> allClasses = new ArrayList<>();

    // Collect all classes for jar file
    try (JarFile jarFile = new JarFile(jarPath)) {
      Enumeration<JarEntry> allEntries = jarFile.entries();
      while (allEntries.hasMoreElements()) {
        JarEntry entry = allEntries.nextElement();
        if (entry.isDirectory()) {
          continue;
        }

        String name = entry.getName();
        if (!name.endsWith(".class")) {
          Log.info("Skipping instrumenting file: " + name);
          continue;
        }

        String className = name.substring(0, name.lastIndexOf(".class"));
        className = className.replace('/', '.');
        allClasses.add(className);
        Log.info("Found class: " + className);
      }
    }

    // No classes found, so none to load. Return errors
    if (allClasses.size() == 0) {
      errorMessages.add("Classes is empty for jar: " + jarPath);
      return errorMessages;
    }

    // Create class loader to load in all classes
    File file = new File(jarPath);
    URL url = file.toURI().toURL();
    URL[] urls = new URL[] {url};
    ClassLoader cl = new URLClassLoader(urls);

    // Loop through all files and load in all classes, agent will instrument them as they load
    for (String className : allClasses) {
      try {
        cl.loadClass(className);
      } catch (UnsupportedClassVersionError ucve) {
        // The classes will still get instrumented here, but warn so the user knows something
        // happened
        Log.warn(ucve.toString());
      } catch (Throwable e) {
        // Catch all exceptions/errors and keep instrumenting to give user the option to manually
        // fix one offs if possible
        errorMessages.add("Failed to instrument class: " + className + ". Error: " + e);
      }
    }

    return errorMessages;
  }

  /**
   * This will create a new jar out of specified original jar and the merge in the instrumented
   * classes from the specified instrumented classes dir
   *
   * @param originalJarPath a path to the original jar.
   * @param instrumentedClassesDir a path to the instrumented classes dir.
   * @param outputZip output file.
   */
  private static void createInstrumentedJar(
      String originalJarPath, String instrumentedClassesDir, String outputZip) throws IOException {
    try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(outputZip))) {
      Set<String> dirFilesToSkip = new HashSet<>();
      dirFilesToSkip.add(".original.class");
      dirFilesToSkip.add(".failed.class");
      Set<String> filesMerged =
          ZipUtils.mergeDirectoryToZip(instrumentedClassesDir, zos, dirFilesToSkip);

      ZipUtils.mergeZipToZip(originalJarPath, zos, filesMerged);
    }
  }
}
