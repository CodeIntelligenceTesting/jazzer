package com.example;

import com.code_intelligence.jazzer.runtime.CoverageMap;
import com.code_intelligence.jazzer.runtime.TraceDataFlowNativeCallbacks;
import java.io.InputStream;
import java.util.Scanner;

//
// Decompiled from StateTrackerTarget.class
//

public class StateTrackerInstrumentedTarget {
    public StateTrackerInstrumentedTarget() {
        CoverageMap.recordCoverage((int)0);
    }

    /*
     * WARNING - void declaration
     */
    public static int computeFoo(int baz, int bar) {
        void var3;
        int var2;
        int var1 = 0;
        int n = 2 * bar;
        CoverageMap.recordCoverage((int)1);
        StateTrackerTarget.use(var1);
        int n2 = baz % 2;
        TraceDataFlowNativeCallbacks.traceConstCmpInt((int)0, (int)n2, (int)226);
        if (n2 == 0) {
            var1 = bar;
            var2 = 3 * bar;
            CoverageMap.recordCoverage((int)2);
        } else {
            var1 = 2 * bar;
            CoverageMap.recordCoverage((int)3);
        }
        int n3 = baz % 3;
        TraceDataFlowNativeCallbacks.traceConstCmpInt((int)0, (int)n3, (int)49);
        if (n3 == 0) {
            var1 += bar;
            CoverageMap.recordCoverage((int)4);
        } else {
            var1 += 2 * bar;
            CoverageMap.recordCoverage((int)5);
        }
        int n4 = var1;
        CoverageMap.recordCoverage((int)6);
        StateTrackerTarget.doSomething();
        int n5 = baz % 4;
        TraceDataFlowNativeCallbacks.traceConstCmpInt((int)0, (int)n5, (int)176);
        if (n5 == 0) {
            CoverageMap.recordCoverage((int)7);
            StateTrackerTarget.use(var1);
            CoverageMap.recordCoverage((int)8);
        } else {
            StateTrackerTarget.use(2 * var1);
            CoverageMap.recordCoverage((int)9);
            StateTrackerTarget.use(var2);
            CoverageMap.recordCoverage((int)10);
        }
        void v3 = var3 + var2;
        CoverageMap.recordCoverage((int)11);
        return (int)v3;
    }

    public static int computeBar(int foo, int baz) {
        int bar;
        block6: {
            switch (baz % 4) {
                default: {
                    CoverageMap.recordCoverage((int)12);
                    break;
                }
                case 0: {
                    bar = baz;
                    CoverageMap.recordCoverage((int)13);
                    break block6;
                }
                case 1: {
                    bar = StateTrackerTarget.compute(baz);
                    CoverageMap.recordCoverage((int)14);
                    break block6;
                }
                case 2: {
                    bar = 5;
                    CoverageMap.recordCoverage((int)15);
                }
            }
            bar = 2 * StateTrackerTarget.compute(baz);
            CoverageMap.recordCoverage((int)16);
        }
        int n = foo;
        TraceDataFlowNativeCallbacks.traceConstCmpInt((int)0, (int)n, (int)199);
        if (n < 0) {
            CoverageMap.recordCoverage((int)17);
            int n2 = StateTrackerTarget.compute(bar);
            CoverageMap.recordCoverage((int)18);
            return n2;
        }
        CoverageMap.recordCoverage((int)19);
        return bar;
    }

    /*
     * WARNING - void declaration
     */
    public static void calculateReward(int quantity, InputStream is) {
        int totalPrice;
        void basePrice;
        void in;
        Scanner scanner = new Scanner(is);
        CoverageMap.recordCoverage((int)20);
        int n = in.nextInt();
        CoverageMap.recordCoverage((int)21);
        int threshold = in.nextInt();
        int price = quantity * basePrice;
        int n2 = quantity;
        TraceDataFlowNativeCallbacks.traceCmpInt((int)n2, (int)500, (int)116);
        if (n2 > 500) {
            CoverageMap.recordCoverage((int)22);
            totalPrice = price + StateTrackerTarget.addDiscount(quantity);
            CoverageMap.recordCoverage((int)23);
        } else {
            totalPrice = price + StateTrackerTarget.addFee(quantity);
            CoverageMap.recordCoverage((int)24);
        }
        int n3 = price;
        int n4 = threshold;
        TraceDataFlowNativeCallbacks.traceCmpInt((int)n3, (int)n4, (int)467);
        if (n3 < n4) {
            CoverageMap.recordCoverage((int)25);
            StateTrackerTarget.printDiscount(totalPrice);
            CoverageMap.recordCoverage((int)26);
        } else {
            StateTrackerTarget.printFee(totalPrice);
            CoverageMap.recordCoverage((int)27);
        }
        CoverageMap.recordCoverage((int)28);
    }

    public static void doSomething() {
        CoverageMap.recordCoverage((int)29);
    }

    public static void use(int var) {
        CoverageMap.recordCoverage((int)30);
    }

    public static int compute(int var) {
        CoverageMap.recordCoverage((int)31);
        return var;
    }

    public static int addDiscount(int var) {
        CoverageMap.recordCoverage((int)32);
        return var;
    }

    public static int addFee(int var) {
        CoverageMap.recordCoverage((int)33);
        return var;
    }

    public static void printDiscount(int var) {
        CoverageMap.recordCoverage((int)34);
    }

    public static void printFee(int var) {
        CoverageMap.recordCoverage((int)35);
    }
}
