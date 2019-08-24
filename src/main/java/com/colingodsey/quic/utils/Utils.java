package com.colingodsey.quic.utils;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

import java.util.function.Consumer;

public class Utils {
    public static byte[] h2ba(String s) {
        final int len = s.length();
        final byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static byte[] createBytes(Consumer<ByteBuf> f, int sizeHint) {
        final ByteBuf buf = Unpooled.buffer(sizeHint);
        f.accept(buf);
        final byte[] out = new byte[buf.readableBytes()];
        buf.readBytes(out);
        return out;
    }

    public static byte[] concat(byte[] a, byte[] b) {
        final byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
