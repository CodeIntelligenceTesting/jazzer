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

package com.code_intelligence.jazzer.generated

private object JavaNoThrowMethods {
    val dataFilePath: String = JavaNoThrowMethods.javaClass.`package`.name.replace('.', '/')
    const val dataFileName = "java_no_throw_methods_list.dat"

    fun readJavaNoThrowMethods(): Set<String> {
        val resource = JavaNoThrowMethods.javaClass.classLoader.getResource("$dataFilePath/$dataFileName")!!
        return resource.openStream().bufferedReader().useLines { line -> line.toSet() }.also {
            println("INFO: Loaded ${it.size} no-throw method signatures")
        }
    }
}

/**
 * A list of Java standard library methods that are known not to throw any exceptions (including
 * [java.lang.RuntimeException], but ignoring [java.lang.VirtualMachineError]).
 *
 * Note: Since methods only declare their thrown exceptions that are not subclasses of [java.lang.RuntimeException],
 * this list cannot be generated purely based on information available via reflection.
 */
val JAVA_NO_THROW_METHODS = JavaNoThrowMethods.readJavaNoThrowMethods()
