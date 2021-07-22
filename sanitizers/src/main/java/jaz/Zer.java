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

package jaz;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.api.Jazzer;
import java.io.IOException;
import java.io.ObjectInputStream;

/**
 * A honeypot class that reports an appropriate finding on any interaction with one of its methods
 * or initializers.
 *
 * Note: This class must not be referenced in any way by the rest of the code, not even statically.
 * When referring to it, always use its hardcoded class name "jaz.Zer".
 */
@SuppressWarnings("unused")
public class Zer implements java.io.Serializable {
  static final long serialVersionUID = 42L;

  private static final Throwable staticInitializerCause;

  static {
    staticInitializerCause = new FuzzerSecurityIssueMedium("finalize call on arbitrary object");
  }

  public Zer() {
    Jazzer.reportFindingFromHook(
        new FuzzerSecurityIssueMedium("default constructor call on arbitrary object"));
  }

  public Zer(String arg1) {
    Jazzer.reportFindingFromHook(
        new FuzzerSecurityIssueMedium("String constructor call on arbitrary object"));
  }

  public Zer(String arg1, Throwable arg2) {
    Jazzer.reportFindingFromHook(
        new FuzzerSecurityIssueMedium("(String, Throwable) constructor call on arbitrary object"));
  }

  private String jaz;

  public String getJaz() {
    Jazzer.reportFindingFromHook(new FuzzerSecurityIssueMedium("getter call on arbitrary object"));
    return jaz;
  }

  public void setJaz(String jaz) {
    Jazzer.reportFindingFromHook(new FuzzerSecurityIssueMedium("setter call on arbitrary object"));
    this.jaz = jaz;
  }

  @Override
  public int hashCode() {
    Jazzer.reportFindingFromHook(
        new FuzzerSecurityIssueMedium("hashCode call on arbitrary object"));
    return super.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    Jazzer.reportFindingFromHook(new FuzzerSecurityIssueMedium("equals call on arbitrary object"));
    return super.equals(obj);
  }

  @Override
  protected Object clone() throws CloneNotSupportedException {
    Jazzer.reportFindingFromHook(new FuzzerSecurityIssueMedium("clone call on arbitrary object"));
    return super.clone();
  }

  @Override
  public String toString() {
    Jazzer.reportFindingFromHook(
        new FuzzerSecurityIssueMedium("toString call on arbitrary object"));
    return super.toString();
  }

  @Override
  protected void finalize() throws Throwable {
    // finalize is invoked automatically by the GC with an uninformative stack trace. We use the
    // stack trace prerecorded in the static initializer.
    Jazzer.reportFindingFromHook(staticInitializerCause);
    super.finalize();
  }

  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    Jazzer.reportFindingFromHook(new FuzzerSecurityIssueHigh("Remote Code Execution\n"
        + "  Deserialization of arbitrary classes with custom readObject may allow remote\n"
        + "  code execution depending on the classpath."));
    in.defaultReadObject();
  }
}
