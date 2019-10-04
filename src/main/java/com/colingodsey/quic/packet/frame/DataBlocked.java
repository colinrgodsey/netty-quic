package com.colingodsey.quic.packet.frame;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.utils.VariableInt;

public class DataBlocked implements Frame {
    public static final int PACKET_ID = 0x14;

    final long dataLimit;

    public DataBlocked(ByteBuf in) {
        Frame.verifyPacketId(in, PACKET_ID);
        dataLimit = VariableInt.read(in);
    }

    public long getDataLimit() {
        return dataLimit;
    }

    public void write(ByteBuf out) {
        VariableInt.write(PACKET_ID, out);
        VariableInt.write(dataLimit, out);
    }

    public int length() {
        return 1 + VariableInt.length(dataLimit);
    }
}
