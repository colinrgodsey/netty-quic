package com.colingodsey.quic.packet.header;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.packet.components.ConnectionID;
import com.colingodsey.quic.utils.VariableInt;

public class ZeroRTTHeader extends LongHeader {
    final int packetNumber;
    final int payloadLength;

    public ZeroRTTHeader(int packetNumber, int version, ConnectionID sourceID,
            ConnectionID destID, int payloadLength) {
        super(Type.ZERO_RTT, getFixedLengthIntBytes(packetNumber), version, sourceID, destID);
        this.payloadLength = payloadLength;
        this.packetNumber = packetNumber;
    }

    ZeroRTTHeader(ByteBuf in) {
        super(in);
        payloadLength = VariableInt.readInt(in);
        packetNumber = readFixedLengthInt(in, getPacketNumberBytes());
    }

    public void write(ByteBuf out) {
        writeLongHeader(out);
        VariableInt.write(payloadLength, out);
        writeFixedLengthInt(packetNumber, getPacketNumberBytes(), out);
    }

    public int getPayloadLength() {
        return payloadLength;
    }

    public int getPacketNumber() {
        return packetNumber;
    }

    public int getPacketNumberBytes() {
        return meta + 1;
    }
}
