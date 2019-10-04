package com.colingodsey.quic.packet;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.packet.component.ConnectionID;

public abstract class ShortHeaderPacket extends Packet {
    boolean spin;
    byte reserved;
    boolean keyPhase;

    public int readHeader(ByteBuf in) {
        final int firstByte = in.readUnsignedByte();

        assert (firstByte >> 7) == 0 : "bad packet form";
        assert ((firstByte >> 6) & 0x1) == 1 : "bad fixed bit";

        spin = ((firstByte >> 5) & 0x1) == 1;
        reserved = (byte) ((firstByte >> 3) & 0x3);
        keyPhase = ((firstByte >> 2) & 0x1) == 1;
        packetNumberBytes = (byte) ((firstByte & 0x3) + 1);

        destID = ConnectionID.read(in);
        packetNumber = readFixedLengthInt(in, packetNumberBytes);

        return 0;
    }

    public ByteBuf writeHeader(ByteBuf out) {
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
        return out;
    }

    public int headerLength() {
        return 1 + destID.length() + packetNumberBytes;
    }
}
