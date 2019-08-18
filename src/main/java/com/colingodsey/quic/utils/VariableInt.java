package com.colingodsey.quic.utils;

import io.netty.buffer.ByteBuf;

public class VariableInt {
    public static long read(final ByteBuf in) {
        final short firstByte = in.readUnsignedByte();
        final int exp = firstByte >> 6;

        long out = firstByte & 0x3F;
        for (int i = 1 << exp ; i > 1 ; i--) {
            out <<= 8;
            out |= in.readUnsignedByte();
        }

        return out;
    }

    public static int readInt(final ByteBuf in) {
        final long value = read(in);

        if ((value >>> 32) != 0) {
            throw new IllegalArgumentException("VariableInt too large for int value");
        }

        return (int) value;
    }

    public static ByteBuf write(final long value, final ByteBuf out) {
        if ((value >>> 6) == 0) {
            out.writeByte((byte) value);
        } else if ((value >>> 14) == 0) {
            out.writeShort(((int) value) | (1 << 14));
        } else if ((value >>> 30) == 0) {
            out.writeInt(((int) value) | (2 << 30));
        } else if ((value >>> 62) == 0) {
            out.writeLong(value | (3L << 62));
        } else if (value < 0) {
            throw new IllegalArgumentException("Value for VariableInt must be positive: " + value);
        } else {
            throw new IllegalArgumentException("Value too big for VariableInt: " + value);
        }

        return out;
    }
}
