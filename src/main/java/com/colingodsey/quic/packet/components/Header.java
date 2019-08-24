package com.colingodsey.quic.packet.components;

import io.netty.buffer.ByteBuf;

public interface Header {
    static Header read(ByteBuf in) {
        final int firstByte = in.getUnsignedByte(in.readerIndex());

        if ((firstByte >> 7) == 1) {
            return new LongHeader(in);
        } else {
            return new ShortHeader(in);
        }
    }

    ConnectionID getDestID();

    default boolean isLong() {
        return this instanceof LongHeader;
    }
}
