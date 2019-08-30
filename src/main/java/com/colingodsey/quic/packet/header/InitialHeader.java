package com.colingodsey.quic.packet.header;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.packet.components.ConnectionID;
import com.colingodsey.quic.utils.VariableInt;

public class InitialHeader extends LongHeader {
    final byte[] token;
    final int packetNumber;
    final int payloadLength;

    public InitialHeader(int version, ConnectionID sourceID,
            ConnectionID destID, byte[] token, int payloadLength, int packetNumber) {
        super(Type.INITIAL, getFixedLengthIntBytes(packetNumber), version, sourceID, destID);
        this.token = token;
        this.payloadLength = payloadLength;
        this.packetNumber = packetNumber;
    }

    InitialHeader(ByteBuf in) {
        super(in);
        token = readBytes(in, VariableInt.readInt(in));
        payloadLength = VariableInt.readInt(in);
        packetNumber = readFixedLengthInt(in, getPacketNumberBytes());
    }

    public void write(ByteBuf out) {
        writeLongHeader(out);
        VariableInt.write(token.length, out).writeBytes(token);
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

    public int getLength() {
        return 0;
    }
}
