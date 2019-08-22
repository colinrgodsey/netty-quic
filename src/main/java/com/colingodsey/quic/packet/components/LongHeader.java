package com.colingodsey.quic.packet.components;

import io.netty.buffer.ByteBuf;

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
    public final ConnectionID sourceID;
    public final ConnectionID destID;

    public LongHeader(ByteBuf in) {
        final int firstByte = in.readUnsignedByte();
        final int typeNum = (firstByte >> 4) & 0x3; //bits 2-4

        assert (firstByte >> 7) == 1 : "bad packet form";
        assert ((firstByte >> 6) & 0x1) == 1 : "bad fixed bit";

        type = Type.values()[typeNum];
        header = (byte) (firstByte & 0xF); //bits 4-8
        version = in.readInt();
        sourceID = new ConnectionID(in);
        destID = new ConnectionID(in);
        check();
    }

    public LongHeader(Type type, byte header, int version, ConnectionID sourceID, ConnectionID destID) {
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
        sourceID.write(out);
        destID.write(out);
    }

    public void check() {
        assert (header >> 4) == 0 : "bad packet header";
    }

    public ConnectionID getDestID() {
        return destID;
    }

    public String toString() {
        return "LongHeader{" +
                "type=" + type +
                ", header=" + header +
                ", version=" + version +
                ", sourceID=" + sourceID +
                ", destID=" + destID +
                '}';
    }
}
