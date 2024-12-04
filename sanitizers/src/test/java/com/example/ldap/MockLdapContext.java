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

package com.example.ldap;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import java.util.Hashtable;
import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.*;

/**
 * Mock LdapContex implementation to test LdapInjection hook configuration.
 *
 * <p>Only {@code com.example.ldap.MockLdapContext#search(java.lang.String, java.lang.String,
 * javax.naming.directory.SearchControls)} is implemented to validate DN and filer query.
 */
public class MockLdapContext implements LdapContext {
  @Override
  public ExtendedResponse extendedOperation(ExtendedRequest request) throws NamingException {
    return null;
  }

  @Override
  public LdapContext newInstance(Control[] requestControls) throws NamingException {
    return this;
  }

  @Override
  public void reconnect(Control[] connCtls) throws NamingException {}

  @Override
  public Control[] getConnectControls() throws NamingException {
    return new Control[0];
  }

  @Override
  public void setRequestControls(Control[] requestControls) throws NamingException {}

  @Override
  public Control[] getRequestControls() throws NamingException {
    return new Control[0];
  }

  @Override
  public Control[] getResponseControls() throws NamingException {
    return new Control[0];
  }

  @Override
  public Attributes getAttributes(Name name) throws NamingException {
    return null;
  }

  @Override
  public Attributes getAttributes(String name) throws NamingException {
    return null;
  }

  @Override
  public Attributes getAttributes(Name name, String[] attrIds) throws NamingException {
    return null;
  }

  @Override
  public Attributes getAttributes(String name, String[] attrIds) throws NamingException {
    return null;
  }

  @Override
  public void modifyAttributes(Name name, int mod_op, Attributes attrs) throws NamingException {}

  @Override
  public void modifyAttributes(String name, int mod_op, Attributes attrs) throws NamingException {}

  @Override
  public void modifyAttributes(Name name, ModificationItem[] mods) throws NamingException {}

  @Override
  public void modifyAttributes(String name, ModificationItem[] mods) throws NamingException {}

  @Override
  public void bind(Name name, Object obj, Attributes attrs) throws NamingException {}

  @Override
  public void bind(String name, Object obj, Attributes attrs) throws NamingException {}

  @Override
  public void rebind(Name name, Object obj, Attributes attrs) throws NamingException {}

  @Override
  public void rebind(String name, Object obj, Attributes attrs) throws NamingException {}

  @Override
  public DirContext createSubcontext(Name name, Attributes attrs) throws NamingException {
    return this;
  }

  @Override
  public DirContext createSubcontext(String name, Attributes attrs) throws NamingException {
    return this;
  }

  @Override
  public DirContext getSchema(Name name) throws NamingException {
    return this;
  }

  @Override
  public DirContext getSchema(String name) throws NamingException {
    return this;
  }

  @Override
  public DirContext getSchemaClassDefinition(Name name) throws NamingException {
    return this;
  }

  @Override
  public DirContext getSchemaClassDefinition(String name) throws NamingException {
    return this;
  }

  @Override
  public NamingEnumeration<SearchResult> search(
      Name name, Attributes matchingAttributes, String[] attributesToReturn)
      throws NamingException {
    return null;
  }

  @Override
  public NamingEnumeration<SearchResult> search(
      String name, Attributes matchingAttributes, String[] attributesToReturn)
      throws NamingException {
    return null;
  }

  @Override
  public NamingEnumeration<SearchResult> search(Name name, Attributes matchingAttributes)
      throws NamingException {
    return null;
  }

  @Override
  public NamingEnumeration<SearchResult> search(String name, Attributes matchingAttributes)
      throws NamingException {
    return null;
  }

  @Override
  public NamingEnumeration<SearchResult> search(Name name, String filter, SearchControls cons)
      throws NamingException {
    return null;
  }

  @Override
  public NamingEnumeration<SearchResult> search(String name, String filter, SearchControls cons)
      throws NamingException {
    // Use UnboundID LDAP to validate DN and filter
    if (!DN.isValidDN(name)) {
      throw new NamingException("Invalid DN " + name);
    }
    try {
      Filter.create(filter);
    } catch (LDAPException e) {
      throw new InvalidSearchFilterException("Invalid search filter " + filter);
    }
    return null;
  }

  @Override
  public NamingEnumeration<SearchResult> search(
      Name name, String filterExpr, Object[] filterArgs, SearchControls cons)
      throws NamingException {
    return null;
  }

  @Override
  public NamingEnumeration<SearchResult> search(
      String name, String filterExpr, Object[] filterArgs, SearchControls cons)
      throws NamingException {
    return null;
  }

  @Override
  public Object lookup(Name name) throws NamingException {
    return this;
  }

  @Override
  public Object lookup(String name) throws NamingException {
    return this;
  }

  @Override
  public void bind(Name name, Object obj) throws NamingException {}

  @Override
  public void bind(String name, Object obj) throws NamingException {}

  @Override
  public void rebind(Name name, Object obj) throws NamingException {}

  @Override
  public void rebind(String name, Object obj) throws NamingException {}

  @Override
  public void unbind(Name name) throws NamingException {}

  @Override
  public void unbind(String name) throws NamingException {}

  @Override
  public void rename(Name oldName, Name newName) throws NamingException {}

  @Override
  public void rename(String oldName, String newName) throws NamingException {}

  @Override
  public NamingEnumeration<NameClassPair> list(Name name) throws NamingException {
    return null;
  }

  @Override
  public NamingEnumeration<NameClassPair> list(String name) throws NamingException {
    return null;
  }

  @Override
  public NamingEnumeration<Binding> listBindings(Name name) throws NamingException {
    return null;
  }

  @Override
  public NamingEnumeration<Binding> listBindings(String name) throws NamingException {
    return null;
  }

  @Override
  public void destroySubcontext(Name name) throws NamingException {}

  @Override
  public void destroySubcontext(String name) throws NamingException {}

  @Override
  public Context createSubcontext(Name name) throws NamingException {
    return this;
  }

  @Override
  public Context createSubcontext(String name) throws NamingException {
    return this;
  }

  @Override
  public Object lookupLink(Name name) throws NamingException {
    return this;
  }

  @Override
  public Object lookupLink(String name) throws NamingException {
    return this;
  }

  @Override
  public NameParser getNameParser(Name name) throws NamingException {
    return null;
  }

  @Override
  public NameParser getNameParser(String name) throws NamingException {
    return null;
  }

  @Override
  public Name composeName(Name name, Name prefix) throws NamingException {
    return null;
  }

  @Override
  public String composeName(String name, String prefix) throws NamingException {
    return null;
  }

  @Override
  public Object addToEnvironment(String propName, Object propVal) throws NamingException {
    return null;
  }

  @Override
  public Object removeFromEnvironment(String propName) throws NamingException {
    return null;
  }

  @Override
  public Hashtable<?, ?> getEnvironment() throws NamingException {
    return null;
  }

  @Override
  public void close() throws NamingException {}

  @Override
  public String getNameInNamespace() throws NamingException {
    return null;
  }
}
