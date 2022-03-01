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
import com.code_intelligence.jazzer.api.Jazzer;
import java.io.Closeable;
import java.io.Flushable;
import java.io.Serializable;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.function.Function;

/**
 * A honeypot class that reports a finding on initialization.
 *
 * Class loading based on externally controlled data could lead to RCE
 * depending on available classes on the classpath. Even if no applicable
 * gadget class is available, allowing input to control class loading is a bad
 * idea and should be prevented. A finding is generated whenever the class
 * is loaded and initialized, regardless of its further use.
 * <p>
 * This class needs to implement {@link Serializable} to be considered in
 * deserialization scenarios. It also implements common constructors, getter
 * and setter and common interfaces to increase chances of passing
 * deserialization checks.
 * <p>
 * <b>Note</b>: Jackson provides a nice list of "nasty classes" at
 * <a
 * href=https://github.com/FasterXML/jackson-databind/blob/2.14/src/main/java/com/fasterxml/jackson/databind/jsontype/impl/SubTypeValidator.java>SubTypeValidator</a>.
 * <p>
 * <b>Note</b>: This class must not be referenced in any way by the rest of the code, not even
 * statically. When referring to it, always use its hardcoded class name {@code jaz.Zer}.
 */
@SuppressWarnings({"rawtypes", "unused"})
public class Zer
    implements Serializable, Cloneable, Comparable<Zer>, Comparator, Closeable, Flushable, Iterable,
               Iterator, Runnable, Callable, Function, Collection, List {
  static final long serialVersionUID = 42L;

  static {
    Jazzer.reportFindingFromHook(new FuzzerSecurityIssueHigh("Remote Code Execution\n"
        + "Unrestricted class loading based on externally controlled data may allow\n"
        + "remote code execution depending on available classes on the classpath."));
  }

  // Common constructors

  public Zer() {}

  public Zer(String arg1) {}

  public Zer(String arg1, Throwable arg2) {}

  // Getter/Setter

  public Object getJaz() {
    return this;
  }

  public void setJaz(String jaz) {}

  // Common interface stubs

  @Override
  public void close() {}

  @Override
  public void flush() {}

  @Override
  public int compareTo(Zer o) {
    return 0;
  }

  @Override
  public int compare(Object o1, Object o2) {
    return 0;
  }

  @Override
  public int size() {
    return 0;
  }

  @Override
  public boolean isEmpty() {
    return false;
  }

  @Override
  public boolean contains(Object o) {
    return false;
  }

  @Override
  public Object[] toArray() {
    return new Object[0];
  }

  @Override
  public boolean add(Object o) {
    return false;
  }

  @Override
  public boolean remove(Object o) {
    return false;
  }

  @Override
  public boolean addAll(Collection c) {
    return false;
  }

  @Override
  public boolean addAll(int index, Collection c) {
    return false;
  }

  @Override
  public void clear() {}

  @Override
  public Object get(int index) {
    return this;
  }

  @Override
  public Object set(int index, Object element) {
    return this;
  }

  @Override
  public void add(int index, Object element) {}

  @Override
  public Object remove(int index) {
    return this;
  }

  @Override
  public int indexOf(Object o) {
    return 0;
  }

  @Override
  public int lastIndexOf(Object o) {
    return 0;
  }

  @Override
  @SuppressWarnings("ConstantConditions")
  public ListIterator listIterator() {
    return null;
  }

  @Override
  @SuppressWarnings("ConstantConditions")
  public ListIterator listIterator(int index) {
    return null;
  }

  @Override
  public List subList(int fromIndex, int toIndex) {
    return this;
  }

  @Override
  public boolean retainAll(Collection c) {
    return false;
  }

  @Override
  public boolean removeAll(Collection c) {
    return false;
  }

  @Override
  public boolean containsAll(Collection c) {
    return false;
  }

  @Override
  public Object[] toArray(Object[] a) {
    return new Object[0];
  }

  @Override
  public Iterator iterator() {
    return this;
  }

  @Override
  public void run() {}

  @Override
  public boolean hasNext() {
    return false;
  }

  @Override
  public Object next() {
    return this;
  }

  @Override
  public Object call() throws Exception {
    return this;
  }

  @Override
  public Object apply(Object o) {
    return this;
  }

  @Override
  @SuppressWarnings("MethodDoesntCallSuperMethod")
  public Object clone() {
    return this;
  }
}
