package com.colingodsey.quic.pipeline.component;

import io.netty.util.ReferenceCountUtil;

import java.util.function.Consumer;

import com.colingodsey.quic.packet.frame.Frame;

import it.unimi.dsi.fastutil.objects.ObjectRBTreeSet;
import it.unimi.dsi.fastutil.objects.ObjectSortedSet;

public class FrameOrdering<T extends Frame.Orderable> {
    protected ObjectSortedSet<T> queue = new ObjectRBTreeSet<>(Frame.Orderable.Comparator.INSTANCE);
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
}
