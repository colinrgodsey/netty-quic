package com.colingodsey.quic.utils;

import io.netty.util.AbstractReferenceCounted;
import io.netty.util.Recycler;
import io.netty.util.ReferenceCountUtil;

import java.util.Objects;

public final class Tuple<A, B> extends AbstractReferenceCounted {
    private static final Recycler<Tuple<?, ?>> recycler = new Recycler<Tuple<?, ?>>() {
        protected Tuple<?, ?> newObject(Handle<Tuple<?, ?>> handle) {
            return new Tuple<>(handle);
        }
    };

    private final Recycler.Handle<Tuple<?, ?>> handle;
    private volatile int cachedHash;
    private A a;
    private B b;

    private Tuple(Recycler.Handle<Tuple<?, ?>> handle) {
        this.handle = handle;
        setRefCnt(0);
    }

    @SuppressWarnings("unchecked")
    public static <A, B> Tuple<A, B> create(A a, B b) {
        final Tuple<A, B> out = (Tuple<A, B>) recycler.get();
        assert out.refCnt() == 0 : "bad reuse";
        out.a = a;
        out.b = b;
        out.cachedHash = -1;
        out.setRefCnt(1);
        return out;
    }

    public A getA() {
        assert refCnt() > 0;
        return a;
    }

    public B getB() {
        assert refCnt() > 0;
        return b;
    }

    public boolean equals(Object o) {
        assert refCnt() > 0;
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final Tuple<?, ?> tuple = (Tuple<?, ?>) o;
        return hashCode() == o.hashCode() &&
                Objects.equals(a, tuple.a) &&
                Objects.equals(b, tuple.b);
    }

    public int hashCode() {
        assert refCnt() > 0;
        if (cachedHash == -1) {
            cachedHash = Objects.hash(a, b);
        }
        return cachedHash;
    }

    public String toString() {
        return "Tuple{" + a + ", " + b + '}';
    }

    protected void deallocate() {
        ReferenceCountUtil.release(a);
        ReferenceCountUtil.release(b);
        a = null;
        b = null;
        handle.recycle(this);
    }

    public Tuple<A, B> touch(Object hint) {
        ReferenceCountUtil.touch(a, hint);
        ReferenceCountUtil.touch(b, hint);
        return this;
    }
}
