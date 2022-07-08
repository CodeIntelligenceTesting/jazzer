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

package com.code_intelligence.jazzer.sanitizers

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh
import com.code_intelligence.jazzer.api.HookType
import com.code_intelligence.jazzer.api.Jazzer
import com.code_intelligence.jazzer.api.MethodHook
import com.code_intelligence.jazzer.api.MethodHooks
import net.sf.jsqlparser.JSQLParserException
import net.sf.jsqlparser.parser.CCJSqlParserUtil
import java.lang.invoke.MethodHandle

/**
 * Detects SQL injections.
 *
 * Untrusted input has to be escaped in such a way that queries remain valid otherwise an injection
 * could be possible. This sanitizer guides the fuzzer to inject insecure characters. If an exception
 * is raised during execution the fuzzer was able to inject an invalid pattern, otherwise all input
 * was escaped correctly.
 *
 * Two types of methods are hooked:
 *   1. Methods that take an SQL query as the first argument (e.g. [java.sql.Statement.execute]).
 *   2. Methods that don't take any arguments and execute an already prepared statement
 *      (e.g. [java.sql.PreparedStatement.execute]).
 * For 1. we validate the syntax of the query using <a href="https://github.com/JSQLParser/JSqlParser">jsqlparser</a>
 * and if both the syntax is invalid and the query execution throws an exception we report an SQL injection.
 * Since we can't reliably validate SQL queries in arbitrary dialects this hook is expected to produce some
 * amount of false positives.
 * For 2. we can't validate the query syntax and therefore only rethrow any exceptions.
 */
@Suppress("unused_parameter", "unused")
object SqlInjection {

    // Characters that should be escaped in user input.
    // See https://dev.mysql.com/doc/refman/8.0/en/string-literals.html
    private const val CHARACTERS_TO_ESCAPE = "'\"\b\n\r\t\\%_"

    private val SQL_SYNTAX_ERROR_EXCEPTIONS = listOf(
        "java.sql.SQLException",
        "java.sql.SQLNonTransientException",
        "java.sql.SQLSyntaxErrorException",
        "org.h2.jdbc.JdbcSQLSyntaxErrorException",
    )

    @MethodHooks(
        MethodHook(type = HookType.REPLACE, targetClassName = "java.sql.Statement", targetMethod = "execute"),
        MethodHook(type = HookType.REPLACE, targetClassName = "java.sql.Statement", targetMethod = "executeBatch"),
        MethodHook(type = HookType.REPLACE, targetClassName = "java.sql.Statement", targetMethod = "executeLargeBatch"),
        MethodHook(type = HookType.REPLACE, targetClassName = "java.sql.Statement", targetMethod = "executeLargeUpdate"),
        MethodHook(type = HookType.REPLACE, targetClassName = "java.sql.Statement", targetMethod = "executeQuery"),
        MethodHook(type = HookType.REPLACE, targetClassName = "java.sql.Statement", targetMethod = "executeUpdate"),
        MethodHook(
            type = HookType.REPLACE,
            targetClassName = "javax.persistence.EntityManager",
            targetMethod = "createNativeQuery"
        )
    )
    @JvmStatic
    fun checkSqlExecute(method: MethodHandle, thisObject: Any?, arguments: Array<Any>, hookId: Int): Any {
        var hasValidSqlQuery = false

        if (arguments.isNotEmpty() && arguments[0] is String) {
            val query = arguments[0] as String
            hasValidSqlQuery = isValidSql(query)
            Jazzer.guideTowardsContainment(query, CHARACTERS_TO_ESCAPE, hookId)
        }
        return try {
            method.invokeWithArguments(thisObject, *arguments)
        } catch (throwable: Throwable) {
            // If we already validated the query string and know it's correct,
            // The exception is likely thrown by a non-existent table or something
            // that we don't want to report.
            if (!hasValidSqlQuery && SQL_SYNTAX_ERROR_EXCEPTIONS.contains(throwable.javaClass.name)) {
                Jazzer.reportFindingFromHook(
                    FuzzerSecurityIssueHigh(
                        """
                    SQL Injection
                    Injected query: ${arguments[0]}
                        """.trimIndent(),
                        throwable
                    )
                )
            }
            throw throwable
        }
    }

    private fun isValidSql(sql: String): Boolean =
        try {
            CCJSqlParserUtil.parseStatements(sql)
            true
        } catch (e: JSQLParserException) {
            false
        } catch (t: Throwable) {
            // Catch any unexpected exceptions so that we don't disturb the
            // instrumented application.
            t.printStackTrace()
            true
        }
}
