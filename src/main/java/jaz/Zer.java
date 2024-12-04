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

package jaz;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.Jazzer;
import java.io.*;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.function.Function;

/**
 * A honeypot class that reports a finding on initialization.
 *
 * <p>Class loading based on externally controlled data could lead to RCE depending on available
 * classes on the classpath. Even if no applicable gadget class is available, allowing input to
 * control class loading is a bad idea and should be prevented. A finding is generated whenever the
 * class is loaded and initialized, regardless of its further use.
 *
 * <p>This class needs to implement {@link Serializable} to be considered in deserialization
 * scenarios. It also implements common constructors, getter and setter and common interfaces to
 * increase chances of passing deserialization checks.
 *
 * <p><b>Note</b>: Jackson provides a nice list of "nasty classes" at <a
 * href=https://github.com/FasterXML/jackson-databind/blob/2.14/src/main/java/com/fasterxml/jackson/databind/jsontype/impl/SubTypeValidator.java>SubTypeValidator</a>.
 *
 * <p><b>Note</b>: This class must not be referenced in any way by the rest of the code, not even
 * statically. When referring to it, always use its hardcoded class name {@code jaz.Zer}.
 */
@SuppressWarnings({"rawtypes", "unused"})
public class Zer
    implements Serializable,
        Cloneable,
        Comparable<Zer>,
        Comparator,
        Closeable,
        Flushable,
        Iterable,
        Iterator,
        Runnable,
        Callable,
        Function,
        Collection,
        List {
  static final long serialVersionUID = 42L;

  // serialized size is 41 bytes
  private static final byte REFLECTIVE_CALL_SANITIZER_ID = 0;
  private static final byte DESERIALIZATION_SANITIZER_ID = 1;
  private static final byte EXPRESSION_LANGUAGE_SANITIZER_ID = 2;

  // A byte representing the relevant sanitizer for a given jaz.Zer instance. It is used to check
  // whether the corresponding sanitizer is disabled and jaz.Zer will not report a finding in this
  // case. Each sanitizer which relies on this class must set this byte accordingly. We choose a
  // single byte to represent the sanitizer in order to keep the serialized version of jaz.Zer
  // objects small (currently 41 bytes) so that it fits in the 64 byte limit of the words that can
  // be used with Jazzer's methods that guide the fuzzer towards generating inputs that contain or
  // are equal to target strings. This limit comes from the corresponding libFuzzer hooks that
  // Jazzer uses under the hood.
  private byte sanitizer = REFLECTIVE_CALL_SANITIZER_ID;

  // Common constructors
  public Zer() {
    reportFindingIfEnabled();
  }

  public Zer(String arg1) {
    reportFindingIfEnabled();
  }

  public Zer(String arg1, Throwable arg2) {
    reportFindingIfEnabled();
  }

  public Zer(byte sanitizer) {
    this.sanitizer = sanitizer;
    reportFindingIfEnabled();
  }

  // A special static method that is called by the expression language injection sanitizer. We
  // choose a parameterless method to keep the string that the sanitizer guides the fuzzer to
  // generate within the 64-byte boundary required by the corresponding guiding methods.
  public static void el() {
    if (isSanitizerEnabled(EXPRESSION_LANGUAGE_SANITIZER_ID)) {
      reportFinding();
    }
  }

  private void reportFindingIfEnabled() {
    if (isSanitizerEnabled(sanitizer)) {
      reportFinding();
    }
  }

  private static void reportFinding() {
    Jazzer.reportFindingFromHook(
        new FuzzerSecurityIssueHigh(
            "Remote Code Execution\n"
                + "Unrestricted class/object creation based on externally controlled data may"
                + " allow\n"
                + "remote code execution depending on available classes on the classpath."));
  }

  private static boolean isSanitizerEnabled(byte sanitizerId) {
    String allDisabledHooks = System.getProperty("jazzer.disabled_hooks");
    if (allDisabledHooks == null || allDisabledHooks.equals("")) {
      return true;
    }

    String sanitizer;
    switch (sanitizerId) {
      case DESERIALIZATION_SANITIZER_ID:
        sanitizer = "com.code_intelligence.jazzer.sanitizers.Deserialization";
        break;
      case EXPRESSION_LANGUAGE_SANITIZER_ID:
        sanitizer = "com.code_intelligence.jazzer.sanitizers.ExpressionLanguageInjection";
        break;
      default:
        sanitizer = "com.code_intelligence.jazzer.sanitizers.ReflectiveCall";
    }
    return Arrays.stream(allDisabledHooks.split(",")).noneMatch(sanitizer::equals);
  }

  // Getter/Setter

  public Object getJaz() {
    reportFindingIfEnabled();
    return this;
  }

  public void setJaz(String jaz) {
    reportFindingIfEnabled();
  }

  @Override
  public int hashCode() {
    reportFindingIfEnabled();
    return super.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    reportFindingIfEnabled();
    return super.equals(obj);
  }

  @Override
  public String toString() {
    reportFindingIfEnabled();
    return super.toString();
  }

  // Common interface stubs

  @Override
  public void close() {
    reportFindingIfEnabled();
  }

  @Override
  public void flush() {
    reportFindingIfEnabled();
  }

  @Override
  public int compareTo(Zer o) {
    reportFindingIfEnabled();
    return 0;
  }

  @Override
  public int compare(Object o1, Object o2) {
    reportFindingIfEnabled();
    return 0;
  }

  @Override
  public int size() {
    reportFindingIfEnabled();
    return 0;
  }

  @Override
  public boolean isEmpty() {
    reportFindingIfEnabled();
    return false;
  }

  @Override
  public boolean contains(Object o) {
    reportFindingIfEnabled();
    return false;
  }

  @Override
  public Object[] toArray() {
    reportFindingIfEnabled();
    return new Object[0];
  }

  @Override
  public boolean add(Object o) {
    reportFindingIfEnabled();
    return false;
  }

  @Override
  public boolean remove(Object o) {
    reportFindingIfEnabled();
    return false;
  }

  @Override
  public boolean addAll(Collection c) {
    reportFindingIfEnabled();
    return false;
  }

  @Override
  public boolean addAll(int index, Collection c) {
    reportFindingIfEnabled();
    return false;
  }

  @Override
  public void clear() {
    reportFindingIfEnabled();
  }

  @Override
  public Object get(int index) {
    reportFindingIfEnabled();
    return this;
  }

  @Override
  public Object set(int index, Object element) {
    reportFindingIfEnabled();
    return this;
  }

  @Override
  public void add(int index, Object element) {
    reportFindingIfEnabled();
  }

  @Override
  public Object remove(int index) {
    reportFindingIfEnabled();
    return this;
  }

  @Override
  public int indexOf(Object o) {
    reportFindingIfEnabled();
    return 0;
  }

  @Override
  public int lastIndexOf(Object o) {
    reportFindingIfEnabled();
    return 0;
  }

  @Override
  @SuppressWarnings("ConstantConditions")
  public ListIterator listIterator() {
    reportFindingIfEnabled();
    return null;
  }

  @Override
  @SuppressWarnings("ConstantConditions")
  public ListIterator listIterator(int index) {
    reportFindingIfEnabled();
    return null;
  }

  @Override
  public List subList(int fromIndex, int toIndex) {
    reportFindingIfEnabled();
    return this;
  }

  @Override
  public boolean retainAll(Collection c) {
    reportFindingIfEnabled();
    return false;
  }

  @Override
  public boolean removeAll(Collection c) {
    reportFindingIfEnabled();
    return false;
  }

  @Override
  public boolean containsAll(Collection c) {
    reportFindingIfEnabled();
    return false;
  }

  @Override
  public Object[] toArray(Object[] a) {
    reportFindingIfEnabled();
    return new Object[0];
  }

  @Override
  public Iterator iterator() {
    reportFindingIfEnabled();
    return this;
  }

  @Override
  public void run() {
    reportFindingIfEnabled();
  }

  @Override
  public boolean hasNext() {
    reportFindingIfEnabled();
    return false;
  }

  @Override
  public Object next() {
    reportFindingIfEnabled();
    return this;
  }

  @Override
  public Object call() throws Exception {
    reportFindingIfEnabled();
    return this;
  }

  @Override
  public Object apply(Object o) {
    reportFindingIfEnabled();
    return this;
  }

  @Override
  @SuppressWarnings("MethodDoesntCallSuperMethod")
  public Object clone() {
    reportFindingIfEnabled();
    return this;
  }

  public Zer reversed() {
    reportFindingIfEnabled();
    return this;
  }

  // readObject calls can directly result in RCE, see https://github.com/frohoff/ysoserial for
  // examples. Since deserialization doesn't call constructors (see
  // https://docs.oracle.com/javase/7/docs/platform/serialization/spec/input.html#2971), we emit a
  // finding right in the readObject method.
  private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
    // Need to read in ourselves to initialize the sanitizer field.
    stream.defaultReadObject();
    reportFindingIfEnabled();
  }
}
