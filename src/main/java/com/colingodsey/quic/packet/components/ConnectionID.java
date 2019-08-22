package com.colingodsey.quic.packet.components;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;

import java.util.Arrays;

public final class ConnectionID {
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

    public void write(ByteBuf out) {
        out.writeByte(bytes.length);
        out.writeBytes(bytes);
    }

    public byte[] getBytes() {
        return bytes.clone();
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        ConnectionID id = (ConnectionID) o;
        return hashCode() == id.hashCode() && Arrays.equals(bytes, id.bytes);
    }

    public int hashCode() {
        if (cachedHash == -1) {
            cachedHash = Arrays.hashCode(bytes);
        }
        return cachedHash;
    }

    public String toString() {
        return "ID{" +
                "bytes=" + ByteBufUtil.hexDump(bytes) +
                '}';
    }
}
