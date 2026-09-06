package com.kbox.core.bfvm;

import java.util.ArrayList;
import java.util.List;

/** Result of protecting a single class. */
public final class BfVmResult {
    public byte[] bytes;
    public final List<String> transformed = new ArrayList<>();
    public final List<String> skipped = new ArrayList<>();

    public boolean isTransformed(String methodName) {
        for (String t : transformed) {
            if (t.startsWith(methodName + "(") || t.equals(methodName)) {
                return true;
            }
        }
        return false;
    }
}
