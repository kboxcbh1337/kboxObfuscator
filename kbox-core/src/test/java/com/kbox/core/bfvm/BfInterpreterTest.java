package com.kbox.core.bfvm;

import com.kbox.core.bfvm.compile.BfProgramWriter;
import com.kbox.runtime.bfvm.BfInterpreter;
import com.kbox.runtime.bfvm.BfVmException;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * Brainfuck interpreter unit tests (ported from the standalone kbox-bfvm module):
 * the runtime {@code BfInterpreter} must faithfully execute the programs the build-side
 * {@link BfProgramWriter} produces, including data round-trips.
 */
public class BfInterpreterTest {

    @Test
    public void helloWorld() {
        String prog = "++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]"
                + ">>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++.";
        assertEquals("Hello World!\n", BfInterpreter.executeToOutput(prog));
    }

    @Test
    public void addTwoCells() {
        // cell0=3, cell1=4; [<+>-] moves cell1 into cell0 -> cell0=7, cell1=0
        int[] tape = BfInterpreter.run("+++>++++[<+>-]", null, null);
        assertEquals(7, tape[0]);
        assertEquals(0, tape[1]);
    }

    @Test
    public void unbalancedBracketsRejected() {
        try {
            BfInterpreter.executeToData("[+");
            fail("expected unbalanced-bracket failure");
        } catch (BfVmException expected) {
            // ok
        }
        try {
            BfInterpreter.executeToData("+]");
            fail("expected unbalanced-bracket failure");
        } catch (BfVmException expected) {
            // ok
        }
    }

    @Test
    public void runawayLoopStopped() {
        try {
            BfInterpreter.executeToOutput("+[]");
            fail("expected step limit failure");
        } catch (BfVmException expected) {
            // ok
        }
    }

    @Test
    public void dataRoundTrip() {
        byte[] data = {0x01, (byte) 0xFE, 0x42, 0x00, (byte) 0xFF, 0x7F, (byte) 0x80};
        String bf = BfProgramWriter.write(data);
        assertArrayEquals(data, BfInterpreter.executeToData(bf));
    }

    @Test
    public void emptyDataRoundTrip() {
        byte[] data = {};
        String bf = BfProgramWriter.write(data);
        assertArrayEquals(data, BfInterpreter.executeToData(bf));
    }
}
