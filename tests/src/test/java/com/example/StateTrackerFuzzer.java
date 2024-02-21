package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class StateTrackerFuzzer {

    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws IOException {
        int quantity = data.consumeInt();
        String input = data.consumeInt() + "\n" + data.consumeInt() + "\n";
        StateTrackerTarget.calculateReward(quantity, new ByteArrayInputStream(input.getBytes()));
    }

}
