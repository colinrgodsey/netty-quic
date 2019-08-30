package com.colingodsey.quic.packet.components;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;

import java.math.BigInteger;
import java.util.Arrays;

public final class ConnectionID {
    public static final ConnectionID EMPTY = new ConnectionID(new byte[0]);

    private final byte[] bytes;
    private volatile int cachedHash = -1;

    public ConnectionID(ByteBuf in) {
        final int length = in.readUnsignedByte();
        bytes = new byte[length];
        assert bytes.length <= 20 : ("too many bytes: " + length);
        in.readBytes(bytes);
    }

    public ConnectionID(byte[] bytes) {
        this.bytes = bytes.clone();
    }

    public ConnectionID(BigInteger bi) {
        this.bytes = bi.toByteArray();
    }

    public ConnectionID(long n) {
        this(BigInteger.valueOf(n));
    }

    public void write(ByteBuf out) {
        out.writeByte(bytes.length);
        out.writeBytes(bytes);
    }

    public byte[] getBytes() {
        return bytes.clone();
    }

    public int length() {
        return bytes.length + 1;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final ConnectionID id = (ConnectionID) o;
        return hashCode() == id.hashCode() && Arrays.equals(bytes, id.bytes);
    }

    public int hashCode() {
        if (cachedHash == -1) {
            cachedHash = Arrays.hashCode(bytes);
        }
        return cachedHash;
    }

    public String toString() {
        return "ConnectionID{" + ByteBufUtil.hexDump(bytes) + '}';
    }
}
