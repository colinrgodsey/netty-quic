package com.colingodsey.quic.packet.components;

import io.netty.buffer.ByteBuf;

import java.math.BigInteger;

import com.colingodsey.quic.packet.Packet;

public class ShortHeader implements Header {
    public final boolean spin;
    public final byte reserved;
    public final boolean keyPhase;
    public final int packetNumber;
    public final BigInteger destID;

    public ShortHeader(ByteBuf in) {
        final int firstByte = in.readUnsignedByte();

        assert (firstByte >> 7) == 0 : "bad packet form";
        assert ((firstByte >> 6) & 0x1) == 1 : "bad fixed bit";

        spin = ((firstByte >> 5) & 0x1) == 1;
        reserved = (byte) ((firstByte >> 3) & 0x3);
        keyPhase = ((firstByte >> 2) & 0x1) == 1;
        final int packetNumberBytes = (firstByte & 0x3) + 1;

        destID = Packet.readID(in);
        packetNumber = Packet.readFixedLengthInt(in, packetNumberBytes);
    }

    public ShortHeader(boolean spin, byte reserved, boolean keyPhase, int packetNumber, BigInteger destID) {
        this.spin = spin;
        this.reserved = reserved;
        this.keyPhase = keyPhase;
        this.packetNumber = packetNumber;
        this.destID = destID;
        check();
    }

    public void write(ByteBuf out) {
        final int packetNumberBytes = Packet.getFixedLengthIntBytes(packetNumber);
        check();
        out.writeByte(
                (0 << 7) | //header form: short
                (1 << 6) | //fixed bit
                ((spin ? 1 : 0) << 5) |
                (reserved << 3) |
                ((keyPhase ? 1 : 0) << 2) |
                (packetNumberBytes - 1)
        );
        Packet.writeID(destID, out);
        Packet.writeFixedLengthInt(packetNumber, packetNumberBytes, out);
    }

    public void check() {
        assert (reserved >> 2) == 0 : "bad reserved bits";
    }

    public BigInteger getDestID() {
        return destID;
    }
}
