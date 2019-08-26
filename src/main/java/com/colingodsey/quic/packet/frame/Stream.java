package com.colingodsey.quic.packet.frame;

import io.netty.buffer.ByteBuf;

import java.util.function.Consumer;

import com.colingodsey.quic.packet.frame.Frame.Orderable;
import com.colingodsey.quic.utils.VariableInt;

public class Stream implements Frame, Orderable {
    public final boolean isFin;
    public final long streamID, offset;
    public final int length;

    public Stream(ByteBuf in) {
        final int packetId = VariableInt.readInt(in);
        assert (packetId >> 3) == 1;
        final boolean hasOffset = (packetId & 0x04) != 0;
        final boolean hasLength = (packetId & 0x02) != 0;
        isFin = (packetId & 0x01) != 0;
        streamID = VariableInt.read(in);
        offset = hasOffset ? VariableInt.read(in) : -1;
        length = hasLength ? VariableInt.readInt(in) : -1;
    }

    public void write(ByteBuf out) {

    }

    public long getOffset() {
        return offset;
    }

    public int getPayloadLength() {
        return 0;
    }

    public long splitAndOrder(long offset, int maxLength, Consumer<Crypto> out) {
        return 0;
    }
}
