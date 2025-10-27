/*
 * Copyright 2025 Code Intelligence GmbH
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
import com.code_intelligence.jazzer.api.Jazzer
import com.code_intelligence.jazzer.api.MethodHook
import com.code_intelligence.jazzer.api.MethodHooks
import org.xml.sax.InputSource
import java.io.InputStream
import java.lang.invoke.MethodHandle

/**
 * Guides XML parser entry points towards patterns that can trigger external resource fetching.
 *
 * This does not report findings directly; it steers inputs so that existing SSRF detection
 * (e.g. Socket/SocketChannel hooks) can observe network connections initiated by XML parsers
 * resolving external entities, schemas, or includes.
 */
@Suppress("unused")
object XmlParserSsrfGuidance {
    private val EXTERNAL_DOCTYPE = "<!DOCTYPE x PUBLIC \"\" \"http://foo\">"
    private val EXTERNAL_DOCTYPE_SIZE = EXTERNAL_DOCTYPE.toByteArray().size

    init {
        require(EXTERNAL_DOCTYPE_SIZE <= 64) {
            "XML exploit must fit in a table of recent compares entry (64 bytes)"
        }
    }

    // Top-level URI fetch guidance when a systemId is provided as a String.
    private const val HTTP_PREFIX = "http://"
    private const val HTTPS_PREFIX = "https://"

    private fun guidePossibleXmlStream(
        arg: Any?,
        hookId: Int,
    ) {
        when (arg) {
            is InputStream -> {
                runCatching {
                    Jazzer.guideTowardsContainment(
                        String(peekMarkableInputStream(arg, EXTERNAL_DOCTYPE_SIZE)),
                        EXTERNAL_DOCTYPE,
                        hookId,
                    )
                }
            }

            is InputSource -> {
                arg.byteStream?.let { stream ->
                    runCatching {
                        Jazzer.guideTowardsContainment(
                            String(peekMarkableInputStream(stream, EXTERNAL_DOCTYPE_SIZE)),
                            EXTERNAL_DOCTYPE,
                            hookId,
                        )
                    }
                }
                arg.characterStream?.let { reader ->
                    runCatching {
                        Jazzer.guideTowardsContainment(
                            peekMarkableReader(reader, EXTERNAL_DOCTYPE_SIZE),
                            EXTERNAL_DOCTYPE,
                            hookId,
                        )
                    }
                }
                // If only a systemId is provided, guide it to be a URL.
                arg.systemId?.let { guidePossibleUrlString(it, hookId) }
            }

            is String -> {
                // Some parse APIs accept a systemId/URI as a String.
                guidePossibleUrlString(arg, hookId)
            }
        }
    }

    private fun guidePossibleUrlString(
        s: String,
        hookId: Int,
    ) {
        Jazzer.guideTowardsContainment(s, HTTP_PREFIX, hookId)
        Jazzer.guideTowardsContainment(s, HTTPS_PREFIX, 31 * hookId)
    }

    // javax.xml.parsers.DocumentBuilder.parse(...)
    @MethodHook(
        type = HookType.BEFORE,
        targetClassName = "javax.xml.parsers.DocumentBuilder",
        targetMethod = "parse",
    )
    @JvmStatic
    fun guideDocumentBuilderParse(
        method: MethodHandle,
        thisObject: Any?,
        arguments: Array<Any>,
        hookId: Int,
    ) {
        if (arguments.isNotEmpty()) {
            guidePossibleXmlStream(arguments[0], hookId)
            if (arguments.size >= 2) guidePossibleXmlStream(arguments[1], 13 * hookId)
        }
    }

    @MethodHook(
        type = HookType.BEFORE,
        targetClassName = "org.xml.sax.XMLReader",
        targetMethod = "parse",
    )
    @JvmStatic
    fun guideXmlReaderParse(
        method: MethodHandle,
        thisObject: Any?,
        arguments: Array<Any>,
        hookId: Int,
    ) {
        if (arguments.isNotEmpty()) {
            guidePossibleXmlStream(arguments[0], hookId)
        }
    }

    @MethodHook(
        type = HookType.BEFORE,
        targetClassName = "javax.xml.parsers.SAXParser",
        targetMethod = "parse",
    )
    @JvmStatic
    fun guideSaxParserParse(
        method: MethodHandle,
        thisObject: Any?,
        arguments: Array<Any>,
        hookId: Int,
    ) {
        if (arguments.isNotEmpty()) {
            // First arg is usually the source (InputStream, InputSource, File, or String systemId).
            guidePossibleXmlStream(arguments[0], hookId)
            if (arguments.size >= 3) {
                // There is an overload parse(InputStream, HandlerBase/DefaultHandler, String systemId)
                guidePossibleXmlStream(arguments[2], 17 * hookId)
            }
        }
    }

    @MethodHooks(
        MethodHook(
            type = HookType.BEFORE,
            targetClassName = "javax.xml.stream.XMLInputFactory",
            targetMethod = "createXMLStreamReader",
        ),
        MethodHook(
            type = HookType.BEFORE,
            targetClassName = "javax.xml.stream.XMLInputFactory",
            targetMethod = "createXMLEventReader",
        ),
    )
    @JvmStatic
    fun guideStaxCreateReader(
        method: MethodHandle,
        thisObject: Any?,
        arguments: Array<Any>,
        hookId: Int,
    ) {
        if (arguments.isNotEmpty()) {
            guidePossibleXmlStream(arguments[0], hookId)
            if (arguments.size >= 2) guidePossibleXmlStream(arguments[1], 19 * hookId)
        }
    }
}
