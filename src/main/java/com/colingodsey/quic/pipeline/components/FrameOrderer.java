package com.colingodsey.quic.pipeline.components;

import io.netty.util.ReferenceCountUtil;

import java.util.Comparator;
import java.util.function.Consumer;

import com.colingodsey.quic.packet.frames.Frame;
import com.colingodsey.quic.packet.frames.Frame.Splittable;

import it.unimi.dsi.fastutil.objects.ObjectRBTreeSet;

public class FrameOrderer<T extends Frame.Splittable> {
    protected ObjectRBTreeSet<T> queue = new ObjectRBTreeSet<>(SplittableComparator.INSTANCE);
    protected long offset = 0;

    public void process(T msg, Consumer<T> out) {
        assert msg.getOffset() >= 0;
        if (msg.getOffset() == offset) {
            ReferenceCountUtil.retain(msg);
            do {
                out.accept(msg);
                queue.remove(msg);
                offset += msg.getPayloadLength();
            } while (!queue.isEmpty() && (msg = queue.first()).getOffset() == offset);
        } else if (msg.getOffset() > offset && !queue.contains(msg)) {
            queue.add(ReferenceCountUtil.retain(msg));
        }
    }

    public int size() {
        int size = 0;
        for (T item : queue) {
            size += item.getPayloadLength();
        }
        return size;
    }

    public void clear() {
        queue.forEach(ReferenceCountUtil::safeRelease);
        queue.clear();
    }

    protected static class SplittableComparator implements Comparator<Splittable> {
        public static final Comparator<Splittable> INSTANCE = new SplittableComparator();

        SplittableComparator() {}

        public int compare(Splittable a, Splittable b) {
            return Long.compare(a.getOffset(), b.getOffset());
        }
    }
}
