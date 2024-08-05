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
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;

@SuppressWarnings("BanJNDI")
public class LdapDnInjection {
  private static final DirContext ctx = new MockLdapContext();

  public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws Exception {
    // Externally provided DN input needs to be escaped properly
    String ou = fuzzedDataProvider.consumeRemainingAsString();
    String base = "ou=" + ou + ",dc=example,dc=com";
    ctx.search(base, "(&(uid=foo)(cn=bar))", new SearchControls());
  }
}
