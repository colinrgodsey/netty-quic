package com.colingodsey.quic.packet;

import io.netty.buffer.ByteBuf;

public class OneRTTPacket extends ShortHeaderPacket {
    private OneRTTPacket() {}

    public static OneRTTPacket create(Packet.Config config, int packetNumber, int packetNumberBytes) {
        final OneRTTPacket out = newEmpty();
        out.type = Type.INITIAL;
        out.packetNumberBytes = (byte) packetNumberBytes;
        out.destID = config.getDestID();
        out.packetNumber = getTruncatedPacketNumber(packetNumber, out.packetNumberBytes);
        return out;
    }

    static OneRTTPacket newEmpty() {
        return new OneRTTPacket();
    }

    @Override
    public int readHeader(ByteBuf in) {
        super.readHeader(in);
        return in.readableBytes();
    }
}
