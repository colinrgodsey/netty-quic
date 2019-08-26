package com.colingodsey.quic.utils;

import java.util.Objects;

public final class Tuple<A, B> {
    private final A a;
    private final B b;
    private volatile int cachedHash = -1;

    public Tuple(A a, B b) {
        this.a = a;
        this.b = b;
    }

    public A getA() {
        return a;
    }

    public B getB() {
        return b;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Tuple<?, ?> tuple = (Tuple<?, ?>) o;
        return hashCode() == o.hashCode() &&
                Objects.equals(a, tuple.a) &&
                Objects.equals(b, tuple.b);
    }

    public int hashCode() {
        if (cachedHash == -1) {
            cachedHash = Objects.hash(a, b);
        }
        return cachedHash;
    }

    public String toString() {
        return "Tuple{" + a + ", " + b + '}';
    }
}
