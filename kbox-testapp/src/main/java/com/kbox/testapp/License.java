package com.kbox.testapp;

/**
 * License-check style routine. This is the type of method you protect most
 * aggressively: it returns a boolean from a small arithmetic check that is
 * easy to verify post-protection (no class hierarchy / reflection needed).
 */
public class License {

    public boolean check(String key) {
        int sum = 0;
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);
            sum += c;
        }
        return (sum % 97) == 1;
    }
}
