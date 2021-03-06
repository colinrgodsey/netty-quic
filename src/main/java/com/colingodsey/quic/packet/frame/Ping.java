package com.colingodsey.quic.packet.frame;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.utils.VariableInt;

//TODO: make high priority
public class Ping implements Frame {
    public static final int PACKET_ID = 0x01;
    public static final Ping INSTANCE = new Ping();

    public static final Ping read(ByteBuf in) {
        Frame.verifyPacketId(in, PACKET_ID);
        return INSTANCE;
    }

    private Ping() {}

    public int length() {
        return 1;
    }

    public void write(ByteBuf out) {
        VariableInt.write(PACKET_ID, out);
    }
}
