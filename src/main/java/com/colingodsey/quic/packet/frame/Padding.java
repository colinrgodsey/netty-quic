package com.colingodsey.quic.packet.frame;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.utils.VariableInt;

public final class Padding implements Frame, Frame.Initial {
    public static final int PACKET_ID = 0x00;
    public static final Padding INSTANCE = new Padding();

    public static final Padding read(ByteBuf in) {
        Frame.verifyPacketId(in, PACKET_ID);
        return INSTANCE;
    }

    private Padding() {}

    public int length() {
        return 1;
    }

    public void write(ByteBuf out) {
        VariableInt.write(PACKET_ID, out);
    }
}
