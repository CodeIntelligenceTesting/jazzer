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
package com.code_intelligence.jazzer.generated;

import com.sun.source.doctree.DocCommentTree;
import com.sun.source.doctree.DocTree;
import com.sun.source.doctree.ThrowsTree;
import com.sun.source.util.DocTrees;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.ModuleElement;
import javax.lang.model.element.PackageElement;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.ArrayType;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.util.ElementFilter;
import jdk.javadoc.doclet.Doclet;
import jdk.javadoc.doclet.DocletEnvironment;
import jdk.javadoc.doclet.Reporter;

/**
 * A Doclet that extracts a list of all method signatures in {@code java.*} that are declared not to
 * throw any exceptions, including {@link RuntimeException} but excluding {@link
 * VirtualMachineError}.
 *
 * Crucially, whereas the throws declaration of a method does not contain subclasses of {@link
 * RuntimeException}, the {@code @throws} Javadoc tag does.
 */
public class NoThrowDoclet implements Doclet {
  private BufferedWriter out;

  @Override
  public void init(Locale locale, Reporter reporter) {}

  @Override
  public String getName() {
    return getClass().getSimpleName();
  }

  @Override
  public Set<? extends Option> getSupportedOptions() {
    return Set.of(new Option() {
      @Override
      public int getArgumentCount() {
        return 1;
      }

      @Override
      public String getDescription() {
        return "Output file (.kt)";
      }

      @Override
      public Kind getKind() {
        return Kind.STANDARD;
      }

      @Override
      public List<String> getNames() {
        return List.of("--out");
      }

      @Override
      public String getParameters() {
        return "<output file (.kt)>";
      }

      @Override
      public boolean process(String option, List<String> args) {
        try {
          out = new BufferedWriter(new FileWriter(args.get(0)));
        } catch (IOException e) {
          e.printStackTrace();
          return false;
        }
        return true;
      }
    });
  }

  @Override
  public SourceVersion getSupportedSourceVersion() {
    return null;
  }

  private String toDescriptor(TypeMirror type) {
    switch (type.getKind()) {
      case BOOLEAN:
        return "Z";
      case BYTE:
        return "B";
      case CHAR:
        return "C";
      case DOUBLE:
        return "D";
      case FLOAT:
        return "F";
      case INT:
        return "I";
      case LONG:
        return "J";
      case SHORT:
        return "S";
      case VOID:
        return "V";
      case ARRAY:
        return "[" + toDescriptor(((ArrayType) type).getComponentType());
      case DECLARED:
        return "L" + getFullyQualifiedName((DeclaredType) type) + ";";
      case TYPEVAR:
        return "Ljava/lang/Object;";
    }
    throw new IllegalArgumentException(
        "Unexpected kind " + type.getKind() + ": " + type.toString());
  }

  private String getFullyQualifiedName(DeclaredType declaredType) {
    TypeElement element = (TypeElement) declaredType.asElement();
    return element.getQualifiedName().toString().replace('.', '/');
  }

  private void handleExecutableElement(DocTrees trees, ExecutableElement executable)
      throws IOException {
    if (!executable.getModifiers().contains(Modifier.PUBLIC))
      return;

    DocCommentTree tree = trees.getDocCommentTree(executable);
    if (tree != null) {
      for (DocTree tag : tree.getBlockTags()) {
        if (tag instanceof ThrowsTree) {
          return;
        }
      }
    }

    String methodName = executable.getSimpleName().toString();
    String className =
        ((TypeElement) executable.getEnclosingElement()).getQualifiedName().toString();
    String internalClassName = className.replace('.', '/');

    String paramTypeDescriptors = executable.getParameters()
                                      .stream()
                                      .map(VariableElement::asType)
                                      .map(this::toDescriptor)
                                      .collect(Collectors.joining(""));
    String returnTypeDescriptor = toDescriptor(executable.getReturnType());
    String methodDescriptor = String.format("(%s)%s", paramTypeDescriptors, returnTypeDescriptor);

    out.write(String.format("%s#%s#%s%n", internalClassName, methodName, methodDescriptor));
  }

  public void handleTypeElement(DocTrees trees, TypeElement typeElement) throws IOException {
    List<ExecutableElement> executables =
        ElementFilter.constructorsIn(typeElement.getEnclosedElements());
    executables.addAll(ElementFilter.methodsIn(typeElement.getEnclosedElements()));
    for (ExecutableElement executableElement : executables) {
      handleExecutableElement(trees, executableElement);
    }
  }

  @Override
  public boolean run(DocletEnvironment docletEnvironment) {
    try {
      DocTrees trees = docletEnvironment.getDocTrees();
      for (ModuleElement moduleElement :
          ElementFilter.modulesIn(docletEnvironment.getSpecifiedElements())) {
        for (PackageElement packageElement :
            ElementFilter.packagesIn(moduleElement.getEnclosedElements())) {
          if (packageElement.getQualifiedName().toString().startsWith("java.")) {
            for (TypeElement typeElement :
                ElementFilter.typesIn(packageElement.getEnclosedElements())) {
              ElementKind kind = typeElement.getKind();
              if (kind == ElementKind.CLASS || kind == ElementKind.ENUM
                  || kind == ElementKind.INTERFACE) {
                handleTypeElement(trees, typeElement);
              }
            }
          }
        }
      }
    } catch (IOException e) {
      e.printStackTrace();
      return false;
    }
    try {
      out.close();
    } catch (IOException e) {
      e.printStackTrace();
      return false;
    }
    return true;
  }
}