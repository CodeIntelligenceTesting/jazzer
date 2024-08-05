/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.instrumentor

import java.io.FileOutputStream

object PatchTestUtils {
    @JvmStatic
    fun classToBytecode(targetClass: Class<*>): ByteArray {
        return ClassLoader
            .getSystemClassLoader()
            .getResourceAsStream("${targetClass.name.replace('.', '/')}.class")!!
            .use {
                it.readBytes()
            }
    }

    @JvmStatic
    fun bytecodeToClass(name: String, bytecode: ByteArray): Class<*> {
        return BytecodeClassLoader(name, bytecode).loadClass(name)
    }

    @JvmStatic
    fun dumpBytecode(outDir: String, name: String, originalBytecode: ByteArray) {
        FileOutputStream("$outDir/$name.class").use { fos -> fos.write(originalBytecode) }
    }

    /**
     * A ClassLoader that dynamically loads a single specified class from byte code and delegates all other class loads to
     * its own ClassLoader.
     */
    class BytecodeClassLoader(val className: String, private val classBytecode: ByteArray) :
        ClassLoader(BytecodeClassLoader::class.java.classLoader) {
        override fun loadClass(name: String): Class<*> {
            if (name != className) {
                return super.loadClass(name)
            }
            return defineClass(className, classBytecode, 0, classBytecode.size)
        }
    }
}

fun assertSelfCheck(target: DynamicTestContract, shouldPass: Boolean = true) {
    val results = target.selfCheck()
    for ((test, passed) in results) {
        if (shouldPass) {
            assert(passed) { "$test should pass" }
        } else {
            assert(!passed) { "$test should not pass" }
        }
    }
}
