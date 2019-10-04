package com.colingodsey.quic.packet.frame;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.utils.VariableInt;

public class MaxStreamData implements Frame {
    public static final int PACKET_ID = 0x11;

    final long streamID;
    final long maxData;

    public MaxStreamData(ByteBuf in) {
        Frame.verifyPacketId(in, PACKET_ID);
        streamID = VariableInt.read(in);
        maxData = VariableInt.read(in);
    }

    public long getMaxData() {
        return maxData;
    }

    public long getStreamID() {
        return streamID;
    }

    public void write(ByteBuf out) {
        VariableInt.write(PACKET_ID, out);
        VariableInt.write(streamID, out);
        VariableInt.write(maxData, out);
    }

    public int length() {
        return 1 +
                VariableInt.length(streamID) +
                VariableInt.length(maxData);
    }
}
