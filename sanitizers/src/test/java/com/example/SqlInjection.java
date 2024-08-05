/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
