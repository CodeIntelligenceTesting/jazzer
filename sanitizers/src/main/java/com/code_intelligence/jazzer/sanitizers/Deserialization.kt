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
        ObjectOutputStream(baos).writeObject(jaz.Ter())
        val serializedJazTerInstance = baos.toByteArray()
        val posToPatch = serializedJazTerInstance.indexOf("jaz.Ter".toByteArray())
        serializedJazTerInstance[posToPatch + "jaz.".length] = 'Z'.code.toByte()
        serializedJazTerInstance
    }

    /**
     * Guides the fuzzer towards producing a valid header for an ObjectInputStream.
     */
    @MethodHook(
        type = HookType.BEFORE,
        targetClassName = "java.io.ObjectInputStream",
        targetMethod = "<init>",
        targetMethodDescriptor = "(Ljava/io/InputStream;)V"
    )
    @JvmStatic
    fun objectInputStreamInitBeforeHook(method: MethodHandle?, alwaysNull: Any?, args: Array<Any?>, hookId: Int) {
        val originalInputStream = args[0] as? InputStream ?: return
        val fixedInputStream = if (originalInputStream.markSupported())
            originalInputStream
        else
            BufferedInputStream(originalInputStream)
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
        targetMethodDescriptor = "(Ljava/io/InputStream;)V"
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
            targetMethod = "readObject"
        ),
        MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.io.ObjectInputStream",
            targetMethod = "readObjectOverride"
        ),
        MethodHook(
            type = HookType.BEFORE,
            targetClassName = "java.io.ObjectInputStream",
            targetMethod = "readUnshared"
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

    /**
     * Calls [Object.finalize] early if the returned object is [jaz.Zer]. A call to finalize is
     * guaranteed to happen at some point, but calling it early means that we can accurately report
     * the input that lead to its execution.
     */
    @MethodHooks(
        MethodHook(type = HookType.AFTER, targetClassName = "java.io.ObjectInputStream", targetMethod = "readObject"),
        MethodHook(type = HookType.AFTER, targetClassName = "java.io.ObjectInputStream", targetMethod = "readObjectOverride"),
        MethodHook(type = HookType.AFTER, targetClassName = "java.io.ObjectInputStream", targetMethod = "readUnshared"),
    )
    @JvmStatic
    fun readObjectAfterHook(
        method: MethodHandle?,
        objectInputStream: ObjectInputStream?,
        args: Array<Any?>,
        hookId: Int,
        deserializedObject: Any?,
    ) {
        if (deserializedObject?.javaClass?.name == HONEYPOT_CLASS_NAME) {
            deserializedObject.javaClass.getDeclaredMethod("finalize").run {
                isAccessible = true
                invoke(deserializedObject)
            }
        }
    }
}
