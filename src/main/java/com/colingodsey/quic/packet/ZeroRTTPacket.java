package com.colingodsey.quic.packet;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.utils.VariableInt;

public class ZeroRTTPacket extends LongHeaderPacket {
    private ZeroRTTPacket() {}

    public static ZeroRTTPacket read(ByteBuf in) {
        final ZeroRTTPacket out = new ZeroRTTPacket();
        out.readData(in);
        return out;
    }

    public static ZeroRTTPacket create(Packet.Config config, int packetNumber) {
        final ZeroRTTPacket out = newEmpty();
        out.type = Type.ZERO_RTT;
        out.packetNumberBytes = config.getPacketNumberBytes();
        out.version = config.getVersion();
        out.sourceID = config.getSourceID();
        out.destID = config.getDestID();
        out.packetNumber = getTruncatedPacketNumber(packetNumber, out.packetNumberBytes);
        return out;
    }

    static ZeroRTTPacket newEmpty() {
        return new ZeroRTTPacket();
    }

    @Override
    public int readHeader(ByteBuf in) {
        super.readHeader(in);
        final int payloadLength = VariableInt.readInt(in);
        packetNumber = readFixedLengthInt(in, getPacketNumberBytes());
        return payloadLength;
    }

    @Override
    public ByteBuf writeHeader(ByteBuf out) {
        final int startIndex = out.readerIndex();
        super.writeHeader(out);
        VariableInt.write(getPayloadLength(), out);
        writeFixedLengthInt(packetNumber, getPacketNumberBytes(), out);
        assert (out.readerIndex() - startIndex) == headerLength();
        return out;
    }

    @Override
    public int headerLength() {
        return super.headerLength() +
                VariableInt.length(getPayloadLength()) +
                getPacketNumberBytes();
    }
}
