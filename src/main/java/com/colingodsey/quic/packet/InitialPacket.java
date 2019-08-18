package com.colingodsey.quic.packet;

import io.netty.buffer.ByteBuf;

import java.math.BigInteger;

import com.colingodsey.quic.packet.components.LongHeader;
import com.colingodsey.quic.packet.components.LongHeader.Type;
import com.colingodsey.quic.utils.VariableInt;

public class InitialPacket implements Packet {
    final LongHeader header;
    final byte[] token;
    final int packetNumber;
    final byte[] payload;

    public InitialPacket(LongHeader header, ByteBuf in) {
        assert header.type == Type.INITIAL;
        this.header = header;
        token = Packet.readBytes(in, VariableInt.readInt(in));
        final int payloadLength = VariableInt.readInt(in);
        packetNumber = Packet.readFixedLengthInt(in, getPacketNumberBytes());
        payload = Packet.readBytes(in, payloadLength);
    }

    public InitialPacket(int version, byte[] token, int packetNumber,
            byte[] payload, BigInteger sourceID, BigInteger destID) {
        final byte packetNumberBytes = (byte) (Packet.getFixedLengthIntBytes(packetNumber) - 1);
        this.header = new LongHeader(Type.INITIAL, packetNumberBytes, version, sourceID, destID);
        this.token = token;
        this.packetNumber = packetNumber;
        this.payload = payload;
    }

    public void write(ByteBuf out) {
        header.write(out);
        VariableInt.write(token.length, out);
        out.writeBytes(token);
        VariableInt.write(payload.length, out);
        Packet.writeFixedLengthInt(packetNumber, getPacketNumberBytes(), out);
        out.writeBytes(payload);
    }

    public int getPacketNumberBytes() {
        return header.header + 1;
    }
}
