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

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;

public class LdapDnInjection {
  private static InitialDirContext ctx;

  public static void fuzzerInitialize() throws NamingException {
    Hashtable<String, String> env = new Hashtable<>();
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.example.ldap.MockInitialContextFactory");
    ctx = new InitialDirContext(env);
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws Exception {
    // Externally provided DN input needs to be escaped properly
    String ou = fuzzedDataProvider.consumeRemainingAsString();
    String base = "ou=" + ou + ",dc=example,dc=com";
    ctx.search(base, "(&(uid=foo)(cn=bar))", new SearchControls());
  }
}
