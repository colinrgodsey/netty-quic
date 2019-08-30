package com.colingodsey.quic.packet.header;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.packet.components.ConnectionID;

public class ShortHeader extends Header {
    public final boolean spin;
    public final byte reserved;
    public final boolean keyPhase;
    public final int packetNumber;
    public final int packetNumberBytes;
    public final ConnectionID destID;

    public ShortHeader(boolean spin, byte reserved, boolean keyPhase, int packetNumber, ConnectionID destID) {
        this.spin = spin;
        this.reserved = reserved;
        this.keyPhase = keyPhase;
        this.packetNumber = packetNumber;
        this.destID = destID;
        packetNumberBytes = getFixedLengthIntBytes(packetNumber);
    }

    ShortHeader(ByteBuf in) {
        final int firstByte = in.readUnsignedByte();

        assert (firstByte >> 7) == 0 : "bad packet form";
        assert ((firstByte >> 6) & 0x1) == 1 : "bad fixed bit";

        spin = ((firstByte >> 5) & 0x1) == 1;
        reserved = (byte) ((firstByte >> 3) & 0x3);
        keyPhase = ((firstByte >> 2) & 0x1) == 1;
        packetNumberBytes = (firstByte & 0x3) + 1;

        destID = new ConnectionID(in);
        packetNumber = readFixedLengthInt(in, packetNumberBytes);
        assert getFixedLengthIntBytes(packetNumber) == packetNumberBytes;
    }

    public void write(ByteBuf out) {
        final int packetNumberBytes = getFixedLengthIntBytes(packetNumber);
        out.writeByte(
                (0 << 7) | //header form: short
                (1 << 6) | //fixed bit
                ((spin ? 1 : 0) << 5) |
                (reserved << 3) |
                ((keyPhase ? 1 : 0) << 2) |
                (packetNumberBytes - 1)
        );
        destID.write(out);
        writeFixedLengthInt(packetNumber, packetNumberBytes, out);
    }

    public ConnectionID getDestID() {
        return destID;
    }

    public boolean isLong() {
        return false;
    }

    public int getPayloadLength() {
        return 0;
    }

    public int getPacketNumber() {
        return packetNumber;
    }

    public int getPacketNumberBytes() {
        return packetNumberBytes;
    }
}
