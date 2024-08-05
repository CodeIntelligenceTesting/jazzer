/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.autofuzz;

import java.util.Stack;
import java.util.stream.Collectors;

public class AutofuzzCodegenVisitor {
  private final Stack<Group> groups = new Stack<>();
  private int variableCounter = 0;

  AutofuzzCodegenVisitor() {
    init();
  }

  private void init() {
    pushGroup("", "", "");
  }

  public void pushGroup(String prefix, String delimiter, String suffix) {
    groups.push(new Group(prefix, delimiter, suffix));
  }

  public void pushElement(String element) {
    groups.peek().push(element);
  }

  public void popElement() {
    groups.peek().pop();
  }

  public void popGroup() {
    if (groups.size() == 1) {
      throw new AutofuzzError(
          "popGroup must be called exactly once for every pushGroup: " + toDebugString());
    }
    pushElement(groups.pop().toString());
  }

  public String generate() {
    if (groups.size() != 1) {
      throw new AutofuzzError(
          "popGroup must be called exactly once for every pushGroup: " + toDebugString());
    }
    return groups.pop().toString();
  }

  public void addCharLiteral(char c) {
    pushElement("'" + escapeForLiteral(Character.toString(c)) + "'");
  }

  public void addStringLiteral(String string) {
    pushElement('"' + escapeForLiteral(string) + '"');
  }

  public String uniqueVariableName() {
    return String.format("autofuzzVariable%s", variableCounter++);
  }

  static String escapeForLiteral(String string) {
    // The list of escape sequences is taken from:
    // https://docs.oracle.com/javase/tutorial/java/data/characters.html
    return string
        .replace("\\", "\\\\")
        .replace("\t", "\\t")
        .replace("\b", "\\b")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\f", "\\f")
        .replace("\"", "\\\"")
        .replace("'", "\\'");
  }

  private String toDebugString() {
    return groups.stream()
        .map(group -> group.elements.stream().collect(Collectors.joining(", ", "[", "]")))
        .collect(Collectors.joining(", ", "[", "]"));
  }

  private static class Group {
    private final String prefix;
    private final String delimiter;
    private final String suffix;
    private final Stack<String> elements = new Stack<>();

    Group(String prefix, String delimiter, String suffix) {
      this.prefix = prefix;
      this.delimiter = delimiter;
      this.suffix = suffix;
    }

    public void push(String element) {
      elements.push(element);
    }

    public void pop() {
      elements.pop();
    }

    @Override
    public String toString() {
      return elements.stream().collect(Collectors.joining(delimiter, prefix, suffix));
    }
  }
}
