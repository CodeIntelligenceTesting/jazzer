package com.code_intelligence.selffuzz;

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.selffuzz.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.selffuzz.jazzer.mutation.mutator.lang.LangMutators;
import com.code_intelligence.selffuzz.jazzer.mutation.support.TypeHolder;
import java.io.DataInputStream;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.EOFException;

import static com.google.common.truth.Truth.assertThat;

class FuzzTestCase {
    @FuzzTest
    void stringMutatorTest(byte[] data) {
        SerializingMutator<String> mutator =
                (SerializingMutator<String>) LangMutators.newFactory().createOrThrow(
                        new TypeHolder<String>() {}.annotatedType());
        if (data.length < 3) {
            return;
        }

        InputStream i = new ByteArrayInputStream(data);
        DataInputStream stream = new DataInputStream(i);

        try {
            String out = mutator.read(stream);
            if (out.equals("asdf")) {
                throw new RuntimeException("asdf");
            }
        } catch (EOFException e) {
            // ignore end of file exceptions which can happen due to an invalid length in the input byte array
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}