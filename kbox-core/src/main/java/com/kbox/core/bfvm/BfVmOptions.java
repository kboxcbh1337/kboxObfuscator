package com.kbox.core.bfvm;

import java.util.function.Predicate;

/**
 * Options controlling which methods of a class are converted into BF programs.
 *
 * <p>The pipeline injector ({@link BfvmMethodInjector}) drives eligibility from the
 * configured {@code bfvmMethods} list and skips constructors; this class remains for
 * the byte[] facade and tests.
 */
public final class BfVmOptions {
    public final Predicate<String> methodNameFilter;
    public final boolean includeCtors;
    public final boolean includeSynchronized;

    public BfVmOptions(Predicate<String> methodNameFilter, boolean includeCtors) {
        this(methodNameFilter, includeCtors, false);
    }

    private BfVmOptions(Predicate<String> methodNameFilter, boolean includeCtors, boolean includeSynchronized) {
        this.methodNameFilter = methodNameFilter;
        this.includeCtors = includeCtors;
        this.includeSynchronized = includeSynchronized;
    }

    public static final BfVmOptions DEFAULT = new BfVmOptions(null, false, false);

    /** Protect every eligible method including constructors. */
    public static BfVmOptions all() {
        return new BfVmOptions(null, true, false);
    }

    /** Protect only methods whose name matches the given predicate. */
    public static BfVmOptions filter(Predicate<String> namePredicate) {
        return new BfVmOptions(namePredicate, false, false);
    }

    public BfVmOptions withCtors(boolean v) {
        return new BfVmOptions(methodNameFilter, v, includeSynchronized);
    }

    public BfVmOptions withSynchronized(boolean v) {
        return new BfVmOptions(methodNameFilter, includeCtors, v);
    }
}
