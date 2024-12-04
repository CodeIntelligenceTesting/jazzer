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

package com.code_intelligence.jazzer.sanitizers;

import static com.code_intelligence.jazzer.sanitizers.utils.ReflectionUtils.INVALID_OFFSET;
import static com.code_intelligence.jazzer.sanitizers.utils.ReflectionUtils.field;
import static com.code_intelligence.jazzer.sanitizers.utils.ReflectionUtils.nestedClass;
import static com.code_intelligence.jazzer.sanitizers.utils.ReflectionUtils.offset;

import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.MethodHook;
import com.code_intelligence.jazzer.utils.UnsafeProvider;
import java.lang.invoke.MethodHandle;
import java.util.WeakHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import sun.misc.Unsafe;

/**
 * The hooks in this class extend the reach of Jazzer's string compare instrumentation to literals
 * (both strings and characters) that are part of regular expression patterns.
 *
 * <p>Internally, the Java standard library represents a compiled regular expression as a graph of
 * instances of Pattern$Node instances, each of which represents a single unit of the full
 * expression and provides a `match` function that takes a {@link Matcher}, a {@link CharSequence}
 * to match against and an index into the sequence. With a hook on this method for every subclass of
 * Pattern$Node, the contents of the node can be inspected and an appropriate string comparison
 * between the relevant part of the input string and the literal string can be reported.
 */
public final class RegexRoadblocks {
  // The number of characters preceding one that failed a character predicate to include in the
  // reported string comparison.
  private static final int CHARACTER_COMPARE_CONTEXT_LENGTH = 10;

  private static final Unsafe UNSAFE = UnsafeProvider.getUnsafe();
  private static final Class<?> SLICE_NODE = nestedClass(Pattern.class, "SliceNode");
  private static final long SLICE_NODE_BUFFER_OFFSET =
      offset(UNSAFE, field(SLICE_NODE, "buffer", int[].class));
  private static final Class<?> CHAR_PREDICATE = nestedClass(Pattern.class, "CharPredicate");
  private static final Class<?> CHAR_PROPERTY = nestedClass(Pattern.class, "CharProperty");
  private static final long CHAR_PROPERTY_PREDICATE_OFFSET =
      offset(
          UNSAFE, field(CHAR_PROPERTY, "predicate", nestedClass(Pattern.class, "CharPredicate")));
  private static final Class<?> BIT_CLASS = nestedClass(Pattern.class, "BitClass");
  private static final long BIT_CLASS_BITS_OFFSET =
      offset(UNSAFE, field(BIT_CLASS, "bits", boolean[].class));

  // Weakly map CharPredicate instances to characters that satisfy the predicate. Since
  // CharPredicate instances are usually lambdas, we collect their solutions by hooking the
  // functions constructing them rather than extracting the solutions via reflection.
  // Note: Java 8 uses anonymous subclasses of CharProperty instead of lambdas implementing
  // CharPredicate, hence CharProperty instances are used as keys instead in that case.
  private static final ThreadLocal<WeakHashMap<Object, Character>> PREDICATE_SOLUTIONS =
      ThreadLocal.withInitial(WeakHashMap::new);

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.regex.Pattern$Node",
      targetMethod = "match",
      targetMethodDescriptor = "(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Z",
      additionalClassesToHook = {
        "java.util.regex.Matcher",
        "java.util.regex.Pattern$BackRef",
        "java.util.regex.Pattern$Behind",
        "java.util.regex.Pattern$BehindS",
        "java.util.regex.Pattern$BmpCharProperty",
        "java.util.regex.Pattern$BmpCharPropertyGreedy",
        "java.util.regex.Pattern$BnM",
        "java.util.regex.Pattern$BnMS",
        "java.util.regex.Pattern$Bound",
        "java.util.regex.Pattern$Branch",
        "java.util.regex.Pattern$BranchConn",
        "java.util.regex.Pattern$CharProperty",
        "java.util.regex.Pattern$CharPropertyGreedy",
        "java.util.regex.Pattern$CIBackRef",
        "java.util.regex.Pattern$Caret",
        "java.util.regex.Pattern$Curly",
        "java.util.regex.Pattern$Conditional",
        "java.util.regex.Pattern$First",
        "java.util.regex.Pattern$GraphemeBound",
        "java.util.regex.Pattern$GroupCurly",
        "java.util.regex.Pattern$GroupHead",
        "java.util.regex.Pattern$GroupRef",
        "java.util.regex.Pattern$LastMatch",
        "java.util.regex.Pattern$LazyLoop",
        "java.util.regex.Pattern$LineEnding",
        "java.util.regex.Pattern$Loop",
        "java.util.regex.Pattern$Neg",
        "java.util.regex.Pattern$NFCCharProperty",
        "java.util.regex.Pattern$NotBehind",
        "java.util.regex.Pattern$NotBehindS",
        "java.util.regex.Pattern$Pos",
        "java.util.regex.Pattern$Ques",
        "java.util.regex.Pattern$Slice",
        "java.util.regex.Pattern$SliceI",
        "java.util.regex.Pattern$SliceIS",
        "java.util.regex.Pattern$SliceS",
        "java.util.regex.Pattern$SliceU",
        "java.util.regex.Pattern$Start",
        "java.util.regex.Pattern$StartS",
        "java.util.regex.Pattern$UnixCaret",
        "java.util.regex.Pattern$UnixDollar",
        "java.util.regex.Pattern$XGrapheme",
      })
  public static void nodeMatchHook(
      MethodHandle method, Object node, Object[] args, int hookId, Boolean matched) {
    if (matched || node == null) return;
    Matcher matcher = (Matcher) args[0];
    if (matcher == null) return;
    int i = (int) args[1];
    CharSequence seq = (CharSequence) args[2];
    if (seq == null) return;

    if (SLICE_NODE != null && SLICE_NODE.isInstance(node)) {
      // The node encodes a match against a fixed string literal. Extract the literal and report a
      // comparison between it and the subsequence of seq starting at i.
      if (SLICE_NODE_BUFFER_OFFSET == INVALID_OFFSET) return;
      int currentLength = limitedLength(matcher.regionEnd() - i);
      String current = seq.subSequence(i, i + currentLength).toString();

      // All the subclasses of SliceNode store the literal in an int[], which we have to truncate to
      // a char[].
      int[] buffer = (int[]) UNSAFE.getObject(node, SLICE_NODE_BUFFER_OFFSET);
      char[] charBuffer = new char[limitedLength(buffer.length)];
      for (int j = 0; j < charBuffer.length; j++) {
        charBuffer[j] = (char) buffer[j];
      }
      String target = new String(charBuffer);

      Jazzer.guideTowardsEquality(current, target, perRegexId(hookId, matcher));
    } else if (CHAR_PROPERTY != null && CHAR_PROPERTY.isInstance(node)) {
      // The node encodes a match against a class of characters, which may be hard to guess unicode
      // characters. We rely on further hooks to track the relation between these nodes and
      // characters satisfying their match function since the nodes themselves encode this
      // information in lambdas, which are difficult to dissect via reflection. If we know a
      // matching character, report a one-character (plus context) string comparison.
      Object solutionKey;
      if (CHAR_PROPERTY_PREDICATE_OFFSET == INVALID_OFFSET) {
        if (CHAR_PREDICATE == null) {
          // We are likely running against JDK 8, which directly construct subclasses of
          // CharProperty rather than using lambdas implementing CharPredicate.
          solutionKey = node;
        } else {
          return;
        }
      } else {
        solutionKey = UNSAFE.getObject(node, CHAR_PROPERTY_PREDICATE_OFFSET);
      }
      if (solutionKey == null) return;
      Character solution = predicateSolution(solutionKey);
      if (solution == null) return;
      // We report a string comparison rather than an integer comparison for two reasons:
      // 1. If the characters are four byte codepoints, they will be coded on six bytes (a surrogate
      //    pair) in CESU-8, which is the encoding assumed for the fuzzer input, whereas ASCII
      //    characters will be coded on a single byte. By using the string compare hook, we do not
      //    have to worry about the encoding at this point.
      // 2. The same character can appear multiple times in both the pattern and the matched string,
      //    which makes it harder for the fuzzer to determine the correct position to mutate the
      //    current character into the matching character. By providing a short section of the
      //    input string preceding the incorrect character, we increase the chance of a hit.
      String context =
          seq.subSequence(Math.max(0, i - CHARACTER_COMPARE_CONTEXT_LENGTH), i).toString();
      String current = seq.subSequence(i, Math.min(i + 1, matcher.regionEnd())).toString();
      String target = Character.toString(solution);
      Jazzer.guideTowardsEquality(context + current, context + target, perRegexId(hookId, matcher));
    }
  }

  // This and all following hooks track the relation between a CharPredicate or CharProperty
  // instance and a character that matches it. We use an after hook on the factory methods so that
  // we have access to the parameters and the created instance at the same time.
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.regex.Pattern",
      targetMethod = "Single",
      targetMethodDescriptor = "(I)Ljava/util/regex/Pattern$BmpCharPredicate;",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.regex.Pattern",
      targetMethod = "SingleI",
      targetMethodDescriptor = "(II)Ljava/util/regex/Pattern$CharPredicate;",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.regex.Pattern",
      targetMethod = "SingleS",
      targetMethodDescriptor = "(I)Ljava/util/regex/Pattern$CharPredicate;",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.regex.Pattern",
      targetMethod = "SingleU",
      targetMethodDescriptor = "(I)Ljava/util/regex/Pattern$CharPredicate;",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  public static void singleHook(
      MethodHandle method, Object node, Object[] args, int hookId, Object predicate) {
    if (predicate == null) return;
    PREDICATE_SOLUTIONS.get().put(predicate, (char) (int) args[0]);
  }

  // Java 8 uses classes extending CharProperty instead of lambdas implementing CharPredicate to
  // match single characters, so also hook those.
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.regex.Pattern$Single",
      targetMethod = "<init>",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.regex.Pattern$SingleI",
      targetMethod = "<init>",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.regex.Pattern$SingleS",
      targetMethod = "<init>",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.regex.Pattern$SingleU",
      targetMethod = "<init>",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  public static void java8SingleHook(
      MethodHandle method, Object property, Object[] args, int hookId, Object alwaysNull) {
    if (property == null) return;
    PREDICATE_SOLUTIONS.get().put(property, (char) (int) args[0]);
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.regex.Pattern",
      targetMethod = "Range",
      targetMethodDescriptor = "(II)Ljava/util/regex/Pattern$CharPredicate;",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.regex.Pattern",
      targetMethod = "CIRange",
      targetMethodDescriptor = "(II)Ljava/util/regex/Pattern$CharPredicate;",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.regex.Pattern",
      targetMethod = "CIRangeU",
      targetMethodDescriptor = "(II)Ljava/util/regex/Pattern$CharPredicate;",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  // Java 8 uses anonymous classes extending CharProperty instead of lambdas implementing
  // CharPredicate to match single characters, so also hook those.
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.regex.Pattern",
      targetMethod = "rangeFor",
      targetMethodDescriptor = "(II)Ljava/util/regex/Pattern$CharProperty;",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.regex.Pattern",
      targetMethod = "caseInsensitiveRangeFor",
      targetMethodDescriptor = "(II)Ljava/util/regex/Pattern$CharProperty;",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  public static void rangeHook(
      MethodHandle method, Object node, Object[] args, int hookId, Object predicate) {
    if (predicate == null) return;
    PREDICATE_SOLUTIONS.get().put(predicate, (char) (int) args[0]);
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.regex.Pattern$CharPredicate",
      targetMethod = "union",
      targetMethodDescriptor =
          "(Ljava/util/regex/Pattern$CharPredicate;)Ljava/util/regex/Pattern$CharPredicate;",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  // Java 8 uses anonymous classes extending CharProperty instead of lambdas implementing
  // CharPredicate to match single characters, so also hook union for those. Even though the classes
  // of the parameters will be different, the actual implementation of the hook is the same in this
  // case.
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.regex.Pattern",
      targetMethod = "union",
      targetMethodDescriptor =
          "(Ljava/util/regex/Pattern$CharProperty;Ljava/util/regex/Pattern$CharProperty;)Ljava/util/regex/Pattern$CharProperty;",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  public static void unionHook(
      MethodHandle method, Object thisObject, Object[] args, int hookId, Object unionPredicate) {
    if (unionPredicate == null) return;
    Character solution = predicateSolution(thisObject);
    if (solution == null) solution = predicateSolution(args[0]);
    if (solution == null) return;
    PREDICATE_SOLUTIONS.get().put(unionPredicate, solution);
  }

  private static Character predicateSolution(Object charPredicate) {
    return PREDICATE_SOLUTIONS
        .get()
        .computeIfAbsent(
            charPredicate,
            unused -> {
              if (BIT_CLASS != null && BIT_CLASS.isInstance(charPredicate)) {
                // BitClass instances have an empty bits array at construction time, so we scan
                // their
                // constants lazily when needed.
                boolean[] bits = (boolean[]) UNSAFE.getObject(charPredicate, BIT_CLASS_BITS_OFFSET);
                for (int i = 0; i < bits.length; i++) {
                  if (bits[i]) {
                    return (char) i;
                  }
                }
              }
              return null;
            });
  }

  // Limits a length to the maximum length libFuzzer will read up to in a callback.
  private static int limitedLength(int length) {
    return Math.min(length, 64);
  }

  // hookId only takes one distinct value per Node subclass. In order to get different regex matches
  // to be tracked similar to different instances of string compares, we mix in the hash of the
  // underlying pattern. We expect patterns to be static almost always, so that this should not fill
  // up the value profile map too quickly.
  private static int perRegexId(int hookId, Matcher matcher) {
    return hookId ^ matcher.pattern().toString().hashCode();
  }
}
