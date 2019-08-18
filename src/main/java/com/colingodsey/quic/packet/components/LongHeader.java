package com.colingodsey.quic.packet.components;

import io.netty.buffer.ByteBuf;

import java.math.BigInteger;

import com.colingodsey.quic.packet.Packet;
import com.colingodsey.quic.utils.QUICRandom;

public class LongHeader implements Header {
    public enum Type {
        INITIAL,
        ZERO_RTT,
        HANDSHAKE,
        RETRY;

        public static Type random() {
            return values()[QUICRandom.nextNibble() % values().length];
        }
    }

    public final Type type;
    public final byte header;
    public final int version;
    public final BigInteger sourceID;
    public final BigInteger destID;

    public LongHeader(ByteBuf in) {
        final int firstByte = in.readUnsignedByte();
        final int typeNum = (firstByte >> 4) & 0x3; //bits 2-4

        assert (firstByte >> 7) == 1 : "bad packet form";
        assert ((firstByte >> 6) & 0x1) == 1 : "bad fixed bit";

        type = Type.values()[typeNum];
        header = (byte) (firstByte & 0xF); //bits 4-8
        version = in.readInt();
        sourceID = Packet.readID(in);
        destID = Packet.readID(in);
        check();
    }

    public LongHeader(Type type, byte header, int version, BigInteger sourceID, BigInteger destID) {
        this.type = type;
        this.header = header;
        this.version = version;
        this.sourceID = sourceID;
        this.destID = destID;
        check();
    }

    public void write(ByteBuf out) {
        check();
        out.writeByte(
                (1 << 7) | //header form: long
                (1 << 6) | //fixed bit
                (type.ordinal() << 4) |
                header
        );
        out.writeInt(version);
        Packet.writeID(sourceID, out);
        Packet.writeID(destID, out);
    }

    public void check() {
        assert (header >> 4) == 0 : "bad packet header";
    }

    public BigInteger getDestID() {
        return destID;
    }
}
