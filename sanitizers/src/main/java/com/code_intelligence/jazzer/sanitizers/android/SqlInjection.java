// Copyright 2023 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.sanitizers.android;

import static java.util.Collections.unmodifiableSet;
import static java.util.stream.Collectors.toSet;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
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
 * Detects SQL injections on Android devices.
 *
 * <p>Untrusted input has to be escaped in such a way that queries remain valid otherwise an
 * injection could be possible. This sanitizer guides the fuzzer to inject insecure characters. If
 * an exception is raised during execution the fuzzer was able to inject an invalid pattern,
 * otherwise all input was escaped correctly.
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
  private static final String CHARACTERS_TO_ESCAPE = "'\"\b\n\r\t\\%_[]^";

  private static final Set<String> HIGH_SEV_SQL_SYNTAX_ERROR_EXCEPTIONS =
      unmodifiableSet(Stream.of("android.database.sqlite.SQLiteException").collect(toSet()));

  private static final Set<String> LOW_SEV_SQL_SYNTAX_ERROR_EXCEPTIONS =
      unmodifiableSet(Stream.of("android.database.sqlite.SQLiteDiskIOException").collect(toSet()));

  @MethodHook(type = HookType.REPLACE, targetClassName = "android.database.sqlite.SQLiteDatabase",
      targetMethod = "execSQL")
  @MethodHook(type = HookType.REPLACE, targetClassName = "android.database.sqlite.SQLiteDatabase",
      targetMethod = "execPerConnectionSQL")
  public static void
  checkSqlExecuteForVoid(MethodHandle method, Object thisObject, Object[] arguments, int hookId)
      throws Throwable {
    boolean hasValidSqlQuery = false;

    if (arguments.length > 0 && arguments[0] instanceof String) {
      String query = (String) arguments[0];
      hasValidSqlQuery = isValidSql(query);
      Jazzer.guideTowardsContainment(query, CHARACTERS_TO_ESCAPE, hookId);
    }
    try {
      method.invokeWithArguments(
          Stream.concat(Stream.of(thisObject), Arrays.stream(arguments)).toArray());
    } catch (Throwable throwable) {
      checkException(throwable, hasValidSqlQuery, arguments);
      throw throwable;
    }
  }

  private static void checkException(
      Throwable throwable, boolean hasValidSqlQuery, Object[] arguments) throws Throwable {
    if (hasValidSqlQuery) {
      // This may not be a security issue but could point to stability issue that needs
      // to be addressed.
      if (LOW_SEV_SQL_SYNTAX_ERROR_EXCEPTIONS.contains(throwable.getClass().getName())) {
        Jazzer.reportFindingFromHook(new FuzzerSecurityIssueLow(
            String.format("SQL Stability Issue%nInjected query: %s%n", arguments[0])));
      }
    }

    if (HIGH_SEV_SQL_SYNTAX_ERROR_EXCEPTIONS.contains(throwable.getClass().getName())) {
      Jazzer.reportFindingFromHook(new FuzzerSecurityIssueHigh(
          String.format("SQL Injection%nInjected query: %s%n", arguments[0])));
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
