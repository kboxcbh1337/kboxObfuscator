package com.kbox.core.analysis;

import java.util.Objects;

/**
 * Immutable reference to a class member (field or method) or a class itself.
 * Used as the key of the dependency graph and the retention decision tree.
 *
 * <p>For class-only references, {@code name} and {@code desc} are empty.
 */
public final class MemberRef {

    public final String owner;   // internal name, e.g. "com/example/Foo"
    public final String name;   // member name, "" for class ref
    public final String desc;   // member descriptor, "" for class ref

    public MemberRef(String owner, String name, String desc) {
        this.owner = owner;
        this.name = name == null ? "" : name;
        this.desc = desc == null ? "" : desc;
    }

    public static MemberRef ofClass(String owner) {
        return new MemberRef(owner, "", "");
    }

    public boolean isClassRef() { return name.isEmpty() && desc.isEmpty(); }

    public String key() {
        return owner + "#" + name + "#" + desc;
    }

    @Override public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof MemberRef)) return false;
        MemberRef r = (MemberRef) o;
        return owner.equals(r.owner) && name.equals(r.name) && desc.equals(r.desc);
    }
    @Override public int hashCode() { return Objects.hash(owner, name, desc); }

    @Override public String toString() {
        return isClassRef() ? owner : (owner + "." + name + desc);
    }
}
