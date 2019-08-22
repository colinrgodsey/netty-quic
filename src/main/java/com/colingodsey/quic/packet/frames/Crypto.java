package com.colingodsey.quic.packet.frames;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.utils.VariableInt;

public class Crypto implements Frame, Frame.Initial {
    public static final int PACKET_ID = 0x06;

    public final int offset;
    public final int length;

    public Crypto(ByteBuf in) {
        Frame.verifyPacketId(in, PACKET_ID);
        offset = VariableInt.readInt(in);
        length = VariableInt.readInt(in);
    }

    public void write(ByteBuf out) {
        VariableInt.write(PACKET_ID, out);
    }
}
