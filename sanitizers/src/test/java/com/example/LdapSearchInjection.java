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
import com.example.ldap.MockLdapContext;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.LdapContext;

@SuppressWarnings("BanJNDI")
public class LdapSearchInjection {
  private static final LdapContext ctx = new MockLdapContext();

  public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws Exception {
    // Externally provided LDAP query input needs to be escaped properly
    String username = fuzzedDataProvider.consumeRemainingAsAsciiString();
    String filter = "(&(uid=" + username + ")(ou=security))";
    ctx.search("dc=example,dc=com", filter, new SearchControls());
  }
}
