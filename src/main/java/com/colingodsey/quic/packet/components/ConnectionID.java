package com.colingodsey.quic.packet.components;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;

import java.math.BigInteger;
import java.util.Arrays;

import com.colingodsey.quic.utils.QUICRandom;

public class ConnectionID {
    public static final ConnectionID EMPTY = new ConnectionID(new byte[0]) {
        @Override
        public String toString() {
            return "ConnectionID.EMPTY";
        }
    };

    private final byte[] bytes;
    private volatile int cachedHash = -1;

    public static ConnectionID random() {
        final int length = 8 + QUICRandom.nextInt(12);
        return new ConnectionID(QUICRandom.nextBytes(length));
    }

    public static ConnectionID read(ByteBuf in) {
        final int length = in.readUnsignedByte();
        if (length == 0) {
            return EMPTY;
        }
        final byte[] bytes = new byte[length];
        assert bytes.length <= 20 : ("too many bytes: " + length);
        in.readBytes(bytes);
        return new ConnectionID(bytes);
    }

    public static ConnectionID read(byte[] bytes) {
        if (bytes.length == 0) {
            return EMPTY;
        }
        return new ConnectionID(bytes);
    }

    ConnectionID(byte[] bytes) {
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
        return "ConnectionID(" + ByteBufUtil.hexDump(bytes) + ')';
    }
}
