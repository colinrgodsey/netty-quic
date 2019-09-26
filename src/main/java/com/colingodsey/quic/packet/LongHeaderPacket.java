package com.colingodsey.quic.packet;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

import com.colingodsey.quic.packet.components.ConnectionID;

public abstract class LongHeaderPacket extends Packet {
    int version;
    ConnectionID sourceID;

    public int readHeader(ByteBuf in) {
        final int firstByte = in.readUnsignedByte();
        final int typeNum = (firstByte >> 4) & 0x3; //bits 2-4

        assert (firstByte >> 7) == 1 : "bad packet form";
        assert ((firstByte >> 6) & 0x1) == 1 : "bad fixed bit";

        type = Type.values()[typeNum];
        assert ((firstByte >> 2) & 0x3) == 0;
        packetNumberBytes = (byte) ((firstByte & 0x3) + 1); //bits 4-8
        version = in.readInt();
        sourceID = ConnectionID.read(in);
        destID = ConnectionID.read(in);

        return 0;
    }

    public ByteBuf writeHeader(ByteBuf out) {
        out.writeByte(
                (1 << 7) | //header form: long
                (1 << 6) | //fixed bit
                (type.ordinal() << 4) |
                (packetNumberBytes - 1)
        );
        out.writeInt(version);
        sourceID.write(out);
        destID.write(out);
        return out;
    }

    public int headerLength() {
        return 1 + 4 + sourceID.length() + destID.length();
    }

    public ConnectionID getSourceID() {
        return sourceID;
    }

    String longHeaderString() {
        return  "type=" + type +
                ", packetNumberBytes=" + packetNumberBytes +
                ", version=" + ByteBufUtil.hexDump(Unpooled.buffer().writeInt(version)) +
                ", sourceID=" + sourceID +
                ", destID=" + destID;
    }
}
