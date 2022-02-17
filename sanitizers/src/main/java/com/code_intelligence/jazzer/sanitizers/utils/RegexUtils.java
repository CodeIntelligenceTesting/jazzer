// Copyright 2022 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.sanitizers.utils;

import static com.code_intelligence.jazzer.sanitizers.utils.ReflectionUtils.clazz;
import static com.code_intelligence.jazzer.sanitizers.utils.ReflectionUtils.constructor;
import static com.code_intelligence.jazzer.sanitizers.utils.ReflectionUtils.field;
import static com.code_intelligence.jazzer.sanitizers.utils.ReflectionUtils.fieldGet;
import static com.code_intelligence.jazzer.sanitizers.utils.ReflectionUtils.fieldOrNull;
import static com.code_intelligence.jazzer.sanitizers.utils.ReflectionUtils.fieldSet;
import static com.code_intelligence.jazzer.sanitizers.utils.ReflectionUtils.intFieldGet;
import static com.code_intelligence.jazzer.sanitizers.utils.ReflectionUtils.nestedClass;
import static com.code_intelligence.jazzer.sanitizers.utils.ReflectionUtils.newInstance;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.regex.Pattern;

public class RegexUtils {
  private static final Class PATTERN = clazz("java.util.regex.Pattern");
  private static final Class NODE = nodeClass("Node");
  private static final Class SLICE_NODE = nodeClass("SliceNode");
  private static final Class BNM = nodeClass("BnM");
  private static final Class BRANCH = nodeClass("Branch");
  private static final Class QUES = nodeClass("Ques");
  private static final Class QTYPE = nodeClass("Qtype");
  private static final Class CHAR_PROPERTY_GREEDY = nodeClass("CharPropertyGreedy");
  private static final Class CURLY = nodeClass("Curly");
  private static final Class PRINT_PATTERN;
  private static final Class CHAR_PROPERTY = nestedClass(PATTERN, "CharProperty");
  private static final Class CHAR_PREDICATE = nestedClass(PATTERN, "CharPredicate");

  private static final Field BRANCH_ATOMS = field(BRANCH, "atoms");
  private static final Field BRANCH_CONN = field(BRANCH, "conn");
  private static final Field PATTERN_MATCH_ROOT;
  private static final Field NODE_NEXT;
  private static final Field SLICE_NODE_BUFFER;
  private static final Field BNM_BUFFER;
  private static final Field PRINT_PATTERN_IDS;
  private static final Field CHAR_PROPERTY_GREEDY_PREDICATE = field(CHAR_PROPERTY_GREEDY, "predicate");
  private static final Field CHAR_PROPERTY_GREEDY_CMIN = field(CHAR_PROPERTY_GREEDY, "cmin");

  private static final Method PRINT_PATTERN_WALK;
  private static final Method BRANCH_ADD;

  private static final Constructor<?> CURLY_CONSTRUCTOR = constructor(CURLY, NODE, int.class, int.class, QTYPE);
  private static final Constructor<?> CHAR_PROPERTY_CONSTRUCTOR = constructor(CHAR_PROPERTY, CHAR_PREDICATE);

  private static final Object ACCEPT_NODE;
  private static final Object QTYPE_GREEDY = QTYPE.getEnumConstants()[0];

  static {
    Field patternRoot;
    try {
      patternRoot = PATTERN.getDeclaredField("matchRoot");
      patternRoot.setAccessible(true);
    } catch (NoSuchFieldException e) {
      patternRoot = null;
      e.printStackTrace();
    }
    PATTERN_MATCH_ROOT = patternRoot;

    Class printPattern;
    try {
      printPattern = Class.forName("java.util.regex.PrintPattern");
    } catch (ClassNotFoundException e) {
      e.printStackTrace();
      printPattern = null;
    }
    PRINT_PATTERN = printPattern;

    Field nodeNext;
    try {
      nodeNext = NODE.getDeclaredField("next");
      nodeNext.setAccessible(true);
    } catch (NoSuchFieldException e) {
      e.printStackTrace();
      nodeNext = null;
    }
    NODE_NEXT = nodeNext;

    Field sliceNodeBuffer;
    try {
      sliceNodeBuffer = SLICE_NODE.getDeclaredField("buffer");
      sliceNodeBuffer.setAccessible(true);
    } catch (NoSuchFieldException e) {
      e.printStackTrace();
      sliceNodeBuffer = null;
    }
    SLICE_NODE_BUFFER = sliceNodeBuffer;

    Field bnmBuffer;
    try {
      bnmBuffer = BNM.getDeclaredField("buffer");
      bnmBuffer.setAccessible(true);
    } catch (NoSuchFieldException e) {
      e.printStackTrace();
      bnmBuffer = null;
    }
    BNM_BUFFER = bnmBuffer;

    Field printPatternIds;
    try {
      printPatternIds = PRINT_PATTERN.getDeclaredField("ids");
      printPatternIds.setAccessible(true);
    } catch (NoSuchFieldException e) {
      e.printStackTrace();
      printPatternIds = null;
    }
    PRINT_PATTERN_IDS = printPatternIds;

    Method printPatternWalk;
    try {
      printPatternWalk = PRINT_PATTERN.getDeclaredMethod("walk", NODE, int.class);
      printPatternWalk.setAccessible(true);
    } catch (NoSuchMethodException e) {
      e.printStackTrace();
      printPatternWalk = null;
    }
    PRINT_PATTERN_WALK = printPatternWalk;

    Method branchAdd;
    try {
      branchAdd = BRANCH.getDeclaredMethod("add", NODE);
      branchAdd.setAccessible(true);
    } catch (NoSuchMethodException e) {
      e.printStackTrace();
      branchAdd = null;
    }
    BRANCH_ADD = branchAdd;

    Object acceptNode;
    try {
      Field acceptNodeField = Pattern.class.getDeclaredField("accept");
      acceptNodeField.setAccessible(true);
      acceptNode = acceptNodeField.get(null);
    } catch (IllegalAccessException | NoSuchFieldException e) {
      e.printStackTrace();
      acceptNode = null;
    }
    ACCEPT_NODE = acceptNode;
  }

  public static Pattern compileRewardPattern(Pattern pattern) {
    Pattern result = Pattern.compile(pattern.pattern(), pattern.flags());
    try {
      PATTERN_MATCH_ROOT.set(result, allowEarlyEnd(PATTERN_MATCH_ROOT.get(result)));
    } catch (IllegalAccessException | InvocationTargetException e) {
      e.printStackTrace();
      return result;
    }
    return result;
  }

  public static void printPattern(Pattern pattern) {
    try {
      PRINT_PATTERN_WALK.invoke(null, PATTERN_MATCH_ROOT.get(pattern), 100);
      ((Map) PRINT_PATTERN_IDS.get(null)).clear();
    } catch (IllegalAccessException | InvocationTargetException e) {
      e.printStackTrace();
    }
  }

  public static Object allowEarlyEnd(final Object root)
      throws IllegalAccessException, InvocationTargetException {
    if (!NODE.isInstance(root)) {
      throw new IllegalArgumentException("root is not an instance of java.util.regex.Pattern$Node");
    }
    Object node = root;
    while (true) {
      Object nextNode = NODE_NEXT.get(node);
      if (nextNode == null || nextNode == ACCEPT_NODE) {
        break;
      }
      Object wrappedNextNode = wrapWithEarlyEndBranch(limitMaxNumRepetitions(nextNode));
      NODE_NEXT.set(node, wrappedNextNode);
      //      if (BRANCH.isInstance(node)) {
      //        Object[] atoms = (Object[]) BRANCH_ATOMS.get(node);
      //        for (int i = 0; i < atoms.length; i++) {
      //          atoms[i] = allowEarlyEnd(atoms[i], maxDepth);
      //        }
      //        BRANCH_ATOMS.set(node, atoms);
      //        BRANCH_ADD.invoke(node, ACCEPT_NODE);
      //
      //        node = BRANCH_CONN.get(node);
      //        continue;
      //      }
      // Continue with the original next node, skipping our wrapper.
      node = nextNode;
    }
    return wrapWithEarlyEndBranch(limitMaxNumRepetitions(root));
  }

  private static String getNodeType(Object node) {
    if (!NODE.isInstance(node)) {
      throw new IllegalArgumentException("node is not an instance of java.util.regex.Pattern$Node");
    }
    return node.getClass().getName().substring("java.util.regex.Pattern$".length());
  }

  private static Object wrapWithEarlyEndBranch(Object node) {
    if (!NODE.isInstance(node)) {
      throw new IllegalArgumentException(
          "node is not an instance of java.util.regex.Pattern$Node: " + node);
    }
    try {
      Constructor quesConstructor = QUES.getDeclaredConstructor(NODE, QTYPE);
      quesConstructor.setAccessible(true);
      return quesConstructor.newInstance(node, QTYPE_GREEDY);
    } catch (InstantiationException | IllegalAccessException | InvocationTargetException
        | NoSuchMethodException e) {
      e.printStackTrace();
      return node;
    }
  }

  private static Object limitMaxNumRepetitions(Object node) {
    checkIsNode(node);

    // Almost all Node types that allow repetitions have a cmin and a cmax field we can set. The
    // only exceptions are the optimized subclasses of CharPropertyGreedy, which we replace by an
    // equivalent Curly.
    if (CHAR_PROPERTY_GREEDY.isInstance(node)) {
      Object predicate = fieldGet(CHAR_PROPERTY_GREEDY_PREDICATE, node);
      Object predicateNode = newInstance(CHAR_PROPERTY_CONSTRUCTOR, predicate);
      int cmin = intFieldGet(CHAR_PROPERTY_GREEDY_CMIN, node);
      // Inlined value of java.util.regex.Pattern.MAX_REPS.
      int cmax = limitedCmaxCount(cmin, 0x7FFFFFFF);
      Object newNode = newInstance(CURLY_CONSTRUCTOR, predicateNode, cmin, cmax, QTYPE_GREEDY);
      fieldSet(NODE_NEXT, newNode, fieldGet(NODE_NEXT, node));
      return newNode;
    }

    Field cminField = fieldOrNull(node.getClass(), "cmin");
    Field cmaxField = fieldOrNull(node.getClass(), "cmax");
    if (cminField == null || cmaxField == null) {
      // Not a node that supports repetition, return unchanged.
      return node;
    }

    fieldSet(cmaxField, node, limitedCmaxCount(intFieldGet(cminField, node), intFieldGet(cmaxField, node)));
    return node;
  }

  private static int limitedCmaxCount(int cmin, int cmax) {
    return Math.min(Math.max(cmin, 1), cmax);
  }

  private static Class<?> nodeClass(String clazzName) {
    return nestedClass(PATTERN, clazzName);
  }

  private static void checkIsNode(Object node) {
    if (!NODE.isInstance(node)) {
      throw new IllegalArgumentException("node is not an instance of java.util.regex.Pattern$Node");
    }
  }
}
