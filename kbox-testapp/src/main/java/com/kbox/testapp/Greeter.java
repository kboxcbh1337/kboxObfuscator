package com.kbox.testapp;

/**
 * Public API entry point of the test application. Its name is deliberately kept
 * (via {@code kbox-testapp.conf}) so external callers can still find it after
 * protection.
 */
public class Greeter {

    /** Returns a localized greeting for the given name. Pure Java (no native). */
    public String greet(String name) {
        if (name == null || name.isEmpty()) {
            name = "world";
        }
        String prefix = decidePrefix(name);
        return prefix + ", " + name + "!";
    }

    /**
     * Picks a prefix. This is the kind of "core algorithm" method the JNIC pass
     * should convert to native code: small, self-contained, easy to verify.
     */
    public String decidePrefix(String name) {
        int hash = 0;
        for (int i = 0; i < name.length(); i++) {
            hash = (hash * 31) + name.charAt(i);
        }
        if ((hash & 1) == 0) return "Hello";
        return "Hi";
    }
}
