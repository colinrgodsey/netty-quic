package com.colingodsey.quic.packet.header;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.packet.components.ConnectionID;
import com.colingodsey.quic.utils.VariableInt;

public class RetryHeader extends LongHeader {
    ConnectionID originalDestID;
    final byte[] token;

    public RetryHeader(int packetNumber, int version, ConnectionID sourceID,
            ConnectionID destID, ConnectionID originalDestID, byte[] token) {
        super(Type.RETRY, getFixedLengthIntBytes(packetNumber), version, sourceID, destID);
        this.originalDestID = originalDestID;
        this.token = token;
    }

    RetryHeader(ByteBuf in) {
        super(in);
        originalDestID = new ConnectionID(in);
        token = readBytes(in, in.readableBytes());
    }

    public void write(ByteBuf out) {
        writeLongHeader(out);
        originalDestID.write(out);
        VariableInt.write(token.length, out).writeBytes(token);
    }

    public int getPacketNumber() {
        return -1;
    }

    public int getPacketNumberBytes() {
        return -1;
    }

    public int getPayloadLength() {
        return 0;
    }
}
