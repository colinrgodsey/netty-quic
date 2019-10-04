package com.colingodsey.quic.packet.frame;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.utils.VariableInt;

public class MaxData implements Frame {
    public static final int PACKET_ID = 0x10;

    final long maxData;

    public MaxData(ByteBuf in) {
        Frame.verifyPacketId(in, PACKET_ID);
        maxData = VariableInt.read(in);
    }

    public long getMaxData() {
        return maxData;
    }

    public void write(ByteBuf out) {
        VariableInt.write(PACKET_ID, out);
        VariableInt.write(maxData, out);
    }

    public int length() {
        return 1 + VariableInt.length(maxData);
    }
}
