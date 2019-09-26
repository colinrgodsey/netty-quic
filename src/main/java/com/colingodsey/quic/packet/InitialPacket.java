package com.colingodsey.quic.packet;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.utils.VariableInt;

public class InitialPacket extends LongHeaderPacket {
    byte[] token;

    private InitialPacket() {}

    public static InitialPacket create(Packet.Config config, long packetNumber) {
        final InitialPacket out = newEmpty();
        out.type = Type.INITIAL;
        out.packetNumberBytes = config.getPacketNumberBytes();
        out.version = config.getVersion();
        out.sourceID = config.getSourceID();
        out.destID = config.getDestID();
        out.token = config.getToken();
        out.packetNumber = getTruncatedPacketNumber(packetNumber, out.packetNumberBytes);
        return out;
    }

    static InitialPacket newEmpty() {
        return new InitialPacket();
    }

    @Override
    public int readHeader(ByteBuf in) {
        super.readHeader(in);
        token = readBytes(in, VariableInt.readInt(in));
        final int payloadLength = VariableInt.readInt(in);
        packetNumber = readFixedLengthInt(in, getPacketNumberBytes());
        return payloadLength;
    }

    @Override
    public ByteBuf writeHeader(ByteBuf out) {
        final int startIndex = out.writerIndex();
        super.writeHeader(out);
        VariableInt.write(token.length, out).writeBytes(token);
        VariableInt.write(getPayloadLength(), out);
        writeFixedLengthInt(packetNumber, getPacketNumberBytes(), out);
        assert (out.writerIndex() - startIndex) == headerLength();
        return out;
    }

    @Override
    public int headerLength() {
        return super.headerLength() +
                VariableInt.length(token.length) + token.length +
                VariableInt.length(getPayloadLength()) +
                getPacketNumberBytes();
    }
}
