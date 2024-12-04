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

package com.code_intelligence.jazzer.sanitizers;

import static java.util.Collections.unmodifiableSet;
import static java.util.stream.Collectors.toSet;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Stream;
import net.sf.jsqlparser.JSQLParserException;
import net.sf.jsqlparser.parser.CCJSqlParserUtil;

/**
 * Detects SQL injections.
 *
 * <p>Untrusted input has to be escaped in such a way that queries remain valid otherwise an
 * injection could be possible. This sanitizer guides the fuzzer to inject insecure characters. If
 * an exception is raised during execution the fuzzer was able to inject an invalid pattern,
 * otherwise all input was escaped correctly.
 *
 * <p>Two types of methods are hooked:
 *
 * <ol>
 *   <li>Methods that take an SQL query as the first argument (e.g. {@link
 *       java.sql.Statement#execute}]).
 *   <li>Methods that don't take any arguments and execute an already prepared statement (e.g.
 *       {@link java.sql.PreparedStatement#execute}).
 * </ol>
 *
 * For 1. we validate the syntax of the query using <a
 * href="https://github.com/JSQLParser/JSqlParser">jsqlparser</a> and if both the syntax is invalid
 * and the query execution throws an exception we report an SQL injection. Since we can't reliably
 * validate SQL queries in arbitrary dialects this hook is expected to produce some amount of false
 * positives. For 2. we can't validate the query syntax and therefore only rethrow any exceptions.
 */
@SuppressWarnings("unused")
public class SqlInjection {
  // Characters that should be escaped in user input.
  // See https://dev.mysql.com/doc/refman/8.0/en/string-literals.html
  private static final String CHARACTERS_TO_ESCAPE = "'\"\b\n\r\t\\%_";

  private static final Set<String> SQL_SYNTAX_ERROR_EXCEPTIONS =
      unmodifiableSet(
          Stream.of(
                  "java.sql.SQLException",
                  "java.sql.SQLNonTransientException",
                  "java.sql.SQLSyntaxErrorException",
                  "org.h2.jdbc.JdbcSQLSyntaxErrorException",
                  "org.h2.jdbc.JdbcSQLFeatureNotSupportedException")
              .collect(toSet()));

  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "java.sql.Statement",
      targetMethod = "execute")
  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "java.sql.Statement",
      targetMethod = "executeBatch")
  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "java.sql.Statement",
      targetMethod = "executeLargeBatch")
  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "java.sql.Statement",
      targetMethod = "executeLargeUpdate")
  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "java.sql.Statement",
      targetMethod = "executeQuery")
  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "java.sql.Statement",
      targetMethod = "executeUpdate")
  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "javax.persistence.EntityManager",
      targetMethod = "createNativeQuery")
  public static Object checkSqlExecute(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) throws Throwable {
    boolean hasValidSqlQuery = false;

    if (arguments.length > 0 && arguments[0] instanceof String) {
      String query = (String) arguments[0];
      hasValidSqlQuery = isValidSql(query);
      Jazzer.guideTowardsContainment(query, CHARACTERS_TO_ESCAPE, hookId);
    }
    try {
      return method.invokeWithArguments(
          Stream.concat(Stream.of(thisObject), Arrays.stream(arguments)).toArray());
    } catch (Throwable throwable) {
      // If we already validated the query string and know it's correct,
      // The exception is likely thrown by a non-existent table or something
      // that we don't want to report.
      if (!hasValidSqlQuery
          && SQL_SYNTAX_ERROR_EXCEPTIONS.contains(throwable.getClass().getName())) {
        Jazzer.reportFindingFromHook(
            new FuzzerSecurityIssueHigh(
                String.format("SQL Injection%nInjected query: %s%n", arguments[0])));
      }
      throw throwable;
    }
  }

  private static boolean isValidSql(String sql) {
    try {
      CCJSqlParserUtil.parseStatements(sql);
      return true;
    } catch (JSQLParserException e) {
      return false;
    } catch (Throwable t) {
      // Catch any unexpected exceptions so that we don't disturb the
      // instrumented application.
      t.printStackTrace();
      return true;
    }
  }
}
