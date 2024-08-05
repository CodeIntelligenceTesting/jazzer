/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.instrumentor;

import com.code_intelligence.jazzer.third_party.org.jacoco.core.internal.instr.InstrSupport;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

public class StaticMethodStrategy implements EdgeCoverageStrategy {
  @Override
  public void instrumentControlFlowEdge(
      MethodVisitor mv, int edgeId, int variable, String coverageMapInternalClassName) {
    InstrSupport.push(mv, edgeId);
    mv.visitMethodInsn(
        Opcodes.INVOKESTATIC, coverageMapInternalClassName, "recordCoverage", "(I)V", false);
  }

  @Override
  public int getInstrumentControlFlowEdgeStackSize() {
    return 1;
  }

  @Override
  public Object getLocalVariableType() {
    return null;
  }

  @Override
  public void loadLocalVariable(
      MethodVisitor mv, int variable, String coverageMapInternalClassName) {}

  @Override
  public int getLoadLocalVariableStackSize() {
    return 0;
  }
}
