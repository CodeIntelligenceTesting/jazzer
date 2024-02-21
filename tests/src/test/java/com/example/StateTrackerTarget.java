package com.example;

import java.io.InputStream;
import java.util.Scanner;

public class StateTrackerTarget {

    public static int computeFoo(int baz, int bar) {
        int var1 = 0;
        int var2 = 2 * bar;
        use(var1);
        if (baz % 2 == 0) {
            var1 = bar;
            var2 = 3 * bar;
        } else {
            var1 = 2 * bar;
        }
        if (baz % 3 == 0) {
            var1 += bar;
        } else {
            var1 += 2 * bar;
        }

        int var3 = var1;
        doSomething();
        if (baz % 4 == 0) {
            use(var1);
        } else {
            use(2 * var1);
            use(var2);
        }
        return var3 + var2;
    }

    public static int computeBar(int foo, int baz) {
        int bar;
        switch (baz % 4) {
            case 0:
                bar = baz;
                break;
            case 1:
                bar = compute(baz);
                break;
            case 2:
                bar = 5;
            default:
                bar = 2 * compute(baz);
                break;
        }
        if (foo < 0) {
            return compute(bar);
        } else {
            return bar;
        }
    }

    public static void calculateReward(int quantity, InputStream is) {
        Scanner in = new Scanner(is);
        int basePrice = in.nextInt();
        int threshold = in.nextInt();
        int price = quantity * basePrice;
        int totalPrice;
        if (quantity > 500) {
            totalPrice = price + addDiscount(quantity);
        } else {
            totalPrice = price + addFee(quantity);
        }
        if (price < threshold) {
            printDiscount(totalPrice);
        } else {
            printFee(totalPrice);
        }
    }

    // The following methods intentionally do nothing, they are just there to get
    // the code above to compile.

    public static void doSomething() {
    }

    public static void use(int var) {
    }

    public static int compute(int var) {
        return var;
    }

    public static int addDiscount(int var) {
        return var;
    }

    public static int addFee(int var) {
        return var;
    }

    public static void printDiscount(int var) {
    }

    public static void printFee(int var) {
    }

}
