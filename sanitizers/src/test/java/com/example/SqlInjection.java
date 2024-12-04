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

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.sql.Connection;
import java.sql.SQLException;
import org.h2.jdbcx.JdbcDataSource;

public class SqlInjection {
  static Connection conn = null;

  public static void fuzzerInitialize() throws Exception {
    JdbcDataSource ds = new JdbcDataSource();
    ds.setURL("jdbc:h2:./test.db");
    conn = ds.getConnection();
    conn.createStatement()
        .execute("CREATE TABLE IF NOT EXISTS pet (id IDENTITY PRIMARY KEY, name VARCHAR(50))");
  }

  static void insecureInsertUser(String userName) throws SQLException {
    // Never use String.format instead of java.sql.Connection.prepareStatement ...
    conn.createStatement().execute(String.format("INSERT INTO pet (name) VALUES ('%s')", userName));
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
    insecureInsertUser(data.consumeRemainingAsString());
  }
}
