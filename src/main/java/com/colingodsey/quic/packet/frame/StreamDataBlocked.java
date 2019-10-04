package com.colingodsey.quic.packet.frame;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.utils.VariableInt;

public class StreamDataBlocked implements Frame {
    public static final int PACKET_ID = 0x15;

    final long streamID;
    final long dataLimit;

    public StreamDataBlocked(ByteBuf in) {
        Frame.verifyPacketId(in, PACKET_ID);
        streamID = VariableInt.read(in);
        dataLimit = VariableInt.read(in);
    }

    public long getStreamID() {
        return streamID;
    }

    public long getDataLimit() {
        return dataLimit;
    }

    public void write(ByteBuf out) {
        VariableInt.write(PACKET_ID, out);
        VariableInt.write(streamID, out);
        VariableInt.write(dataLimit, out);
    }

    public int length() {
        return 1 +
                VariableInt.length(streamID) +
                VariableInt.length(dataLimit);
    }
}
