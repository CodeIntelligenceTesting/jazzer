// Copyright 2022 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.static_analysis

import soot.ClassProvider
import soot.ClassSource
import soot.FoundFile
import soot.SootClass
import soot.asm.AsmClassSource
import soot.javaToJimple.IInitialResolver
import java.lang.reflect.Constructor
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeBytes

/**
 * A Soot [ClassProvider] that applies Jazzer's instrumentation to a class before passing it on to Soot.
 *
 * Note: Since Jazzer coverage IDs need to be globally unique, this provider can't just read the bytecode from the
 *       .class file, but has to load the class to trigger agent instrumentation. This may lead to problems if the
 *       fuzz target expects classes to be loaded with custom ClassLoaders.
 */
object InstrumentedClassProvider : ClassProvider {
    private val instrumentedClasses = mutableMapOf<String, ByteArray>()

    fun registerInstrumentedClass(internalClassName: String, instrumentedBytecode: ByteArray) {
        instrumentedClasses[internalClassName] = instrumentedBytecode
    }

    private fun getInstrumentedBytecode(className: String): ByteArray? {
        return instrumentedClasses[className.replace('.', '/')]
    }

    private fun getUninstrumentedBytecode(clazz: Class<*>): ByteArray? {
        val classResourceName = "/${clazz.name.replace('.', '/')}.class"
        return clazz.getResourceAsStream(classResourceName)?.readAllBytes()
    }

    override fun find(className: String): ClassSource? {
        val clazz = try {
            // InstrumentedClassProvider's ClassLoader is the bootstrap loader and hence null, so the only usable
            // ClassLoader at this point is the system ClassLoader.
            ClassLoader.getSystemClassLoader().loadClass(className)
        } catch (e: ClassNotFoundException) {
            println("WARN: Failed to load $className for Soot")
            return null
        }
        val bytecode: ByteArray = getInstrumentedBytecode(className) ?: getUninstrumentedBytecode(clazz) ?: return null
        return BytecodeClassSource(className, bytecode)
    }
}

/**
 * A Soot [ClassSource] that loads a class from bytecode.
 */
private class BytecodeClassSource(className: String, bytecode: ByteArray) : ClassSource(className) {
    private val classSource: ClassSource

    init {
        // Soot's AsmClassSource only accepts File inputs, not InputStream, so
        // we have to take a detour through a temporary file.
        val tempFile = Files.createTempFile(bytecodeTempDir, null, ".class")
        tempFile.toFile().deleteOnExit()
        tempFile.writeBytes(bytecode)
        classSource = asmClassSourceConstructor.newInstance(className, FoundFile(tempFile.toFile()))
    }

    override fun resolve(clazz: SootClass?): IInitialResolver.Dependencies {
        return classSource.resolve(clazz)
    }

    companion object {
        private val asmClassSourceConstructor: Constructor<AsmClassSource> =
            AsmClassSource::class.java.getDeclaredConstructor(String::class.java, FoundFile::class.java)
        private val bytecodeTempDir: Path = createTempDirectory("jazzer-bytecode-class-source")

        init {
            asmClassSourceConstructor.isAccessible = true
            bytecodeTempDir.toFile().deleteOnExit()
        }
    }
}

enum class SootPhase(val string: String) {
    CG("cg"),
    CG_SPARK("cg.spark"),
    CG_CHA("cg.cha"),
    JOP("jop"),
    JB("jb"),
    JAP("jap")
}

enum class CallGraphAlgorithm {
    CHA,
    RTA,
    VTA,
    SPARK,
    SPARK_LIBRARY
}
