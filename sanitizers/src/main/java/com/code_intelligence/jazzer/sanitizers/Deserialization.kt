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

package com.code_intelligence.jazzer.sanitizers

import com.code_intelligence.jazzer.api.HookType
import com.code_intelligence.jazzer.api.MethodHook
import com.code_intelligence.jazzer.api.MethodHooks
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.io.ObjectStreamConstants
import java.lang.invoke.MethodHandle
import java.util.WeakHashMap

/**
 * Detects unsafe deserialization that leads to attacker-controlled method calls, in particular to [Object.finalize].
 */
@Suppress("unused_parameter", "unused")
object Deserialization {
    private val OBJECT_INPUT_STREAM_HEADER =
        ObjectStreamConstants.STREAM_MAGIC.toBytes() + ObjectStreamConstants.STREAM_VERSION.toBytes()

    init {
        require(OBJECT_INPUT_STREAM_HEADER.size <= 64) {
            "Object input stream header must fit in a table of recent compares entry (64 bytes)"
        }
    }

    /**
     * Used to memoize the [InputStream] used to construct a given [ObjectInputStream].
     * [ThreadLocal] is required because the map is not synchronized (and likely cheaper than
     * synchronization).
     * [WeakHashMap] ensures that we don't prevent the GC from cleaning up [ObjectInputStream] from
     * previous fuzzing runs.
     *
     * Note: The [InputStream] values can all be assumed to be markable, i.e., their
     * [InputStream.markSupported] returns true.
     */
    private var inputStreamForObjectInputStream: ThreadLocal<WeakHashMap<ObjectInputStream, InputStream>> =
        ThreadLocal.withInitial {
            WeakHashMap<ObjectInputStream, InputStream>()
        }

    /**
     * A serialized instance of our honeypot class.
     */
    private val SERIALIZED_JAZ_ZER_INSTANCE: ByteArray by lazy {
        // We can't instantiate jaz.Zer directly, so we instantiate and serialize jaz.Ter and then
        // patch the class name.
        val baos = ByteArrayOutputStream()
        ObjectOutputStream(baos).writeObject(jaz.Ter(jaz.Ter.EXPRESSION_LANGUAGE_SANITIZER_ID))
        val serializedJazTerInstance = baos.toByteArray()
        val posToPatch = serializedJazTerInstance.indexOf("jaz.Ter".toByteArray())
        serializedJazTerInstance[posToPatch + "jaz.".length] = 'Z'.code.toByte()
        serializedJazTerInstance
    }

    init {
        require(SERIALIZED_JAZ_ZER_INSTANCE.size <= 64) {
            "Serialized jaz.Zer instance must fit in a table of recent compares entry (64 bytes)"
        }
    }

    /**
     * Guides the fuzzer towards producing a valid header for an ObjectInputStream.
     */
    @MethodHook(
        type = HookType.BEFORE,
        targetClassName = "java.io.ObjectInputStream",
        targetMethod = "<init>",
        targetMethodDescriptor = "(Ljava/io/InputStream;)V",
    )
    @JvmStatic
    fun objectInputStreamInitBeforeHook(
        method: MethodHandle?,
        alwaysNull: Any?,
        args: Array<Any?>,
        hookId: Int,
    ) {
        val originalInputStream = args[0] as? InputStream ?: return
        val fixedInputStream =
            if (originalInputStream.markSupported()) {
                originalInputStream
            } else {
                BufferedInputStream(originalInputStream)
            }
        args[0] = fixedInputStream
        guideMarkableInputStreamTowardsEquality(fixedInputStream, OBJECT_INPUT_STREAM_HEADER, hookId)
    }

    /**
     * Memoizes the input stream used for creating the [ObjectInputStream] instance.
     */
    @MethodHook(
        type = HookType.AFTER,
        targetClassName = "java.io.ObjectInputStream",
        targetMethod = "<init>",
        targetMethodDescriptor = "(Ljava/io/InputStream;)V",
    )
    @JvmStatic
    fun objectInputStreamInitAfterHook(
        method: MethodHandle?,
        objectInputStream: ObjectInputStream?,
        args: Array<Any?>,
        hookId: Int,
        alwaysNull: Any?,
    ) {
        val inputStream = args[0] as? InputStream
        check(inputStream?.markSupported() == true) {
            "ObjectInputStream#<init> AFTER hook reached with null or non-markable input stream"
        }
        inputStreamForObjectInputStream.get()[objectInputStream] = inputStream
    }

    /**
     * Guides the fuzzer towards producing a valid serialized instance of our honeypot class.
     */
    @MethodHooks(
        MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.io.ObjectInputStream",
            targetMethod = "readObject",
        ),
        MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.io.ObjectInputStream",
            targetMethod = "readObjectOverride",
        ),
        MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.io.ObjectInputStream",
            targetMethod = "readUnshared",
        ),
    )
    @JvmStatic
    fun readObjectBeforeHook(
        method: MethodHandle?,
        objectInputStream: ObjectInputStream?,
        args: Array<Any?>,
        hookId: Int,
    ) {
        val inputStream = inputStreamForObjectInputStream.get()[objectInputStream]
        if (inputStream?.markSupported() != true) return
        guideMarkableInputStreamTowardsEquality(inputStream, SERIALIZED_JAZ_ZER_INSTANCE, hookId)
    }
}
