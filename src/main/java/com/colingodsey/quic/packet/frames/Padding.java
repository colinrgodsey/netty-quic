package com.colingodsey.quic.packet.frames;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.utils.VariableInt;

public class Padding implements Frame {
    public static final int PACKET_ID = 0x00;
    public static final Padding INSTANCE = new Padding();

    public static final Padding read(ByteBuf in) {
        final long packetId = VariableInt.read(in);
        assert packetId == PACKET_ID;
        return INSTANCE;
    }

    private Padding() {}

    public void write(ByteBuf out) {
        VariableInt.write(PACKET_ID, out);
    }
}
