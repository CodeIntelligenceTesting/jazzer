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

package com.code_intelligence.jazzer.instrumentor

import java.io.FileOutputStream

object PatchTestUtils {
    @JvmStatic
    fun classToBytecode(targetClass: Class<*>): ByteArray =
        ClassLoader
            .getSystemClassLoader()
            .getResourceAsStream("${targetClass.name.replace('.', '/')}.class")!!
            .use {
                it.readBytes()
            }

    @JvmStatic
    fun bytecodeToClass(
        name: String,
        bytecode: ByteArray,
    ): Class<*> = BytecodeClassLoader(name, bytecode).loadClass(name)

    @JvmStatic
    fun dumpBytecode(
        outDir: String,
        name: String,
        originalBytecode: ByteArray,
    ) {
        FileOutputStream("$outDir/$name.class").use { fos -> fos.write(originalBytecode) }
    }

    /**
     * A ClassLoader that dynamically loads a single specified class from byte code and delegates all other class loads to
     * its own ClassLoader.
     */
    class BytecodeClassLoader(
        val className: String,
        private val classBytecode: ByteArray,
    ) : ClassLoader(BytecodeClassLoader::class.java.classLoader) {
        override fun loadClass(name: String): Class<*> {
            if (name != className) {
                return super.loadClass(name)
            }
            return defineClass(className, classBytecode, 0, classBytecode.size)
        }
    }
}

fun assertSelfCheck(
    target: DynamicTestContract,
    shouldPass: Boolean = true,
) {
    val results = target.selfCheck()
    for ((test, passed) in results) {
        if (shouldPass) {
            assert(passed) { "$test should pass" }
        } else {
            assert(!passed) { "$test should not pass" }
        }
    }
}
