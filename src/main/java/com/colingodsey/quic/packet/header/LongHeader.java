package com.colingodsey.quic.packet.header;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

import java.util.function.Function;

import com.colingodsey.quic.packet.components.ConnectionID;
import com.colingodsey.quic.utils.QUICRandom;

public abstract class LongHeader extends Header {
    public final Type type;
    public final byte meta;
    public final int version;
    public final ConnectionID sourceID;
    public final ConnectionID destID;

    public static LongHeader read(ByteBuf in) {
        final int firstByte = in.getUnsignedByte(in.readerIndex());
        return Type.values()[(firstByte >> 4) & 0x3].cons.apply(in);
    }

    LongHeader(ByteBuf in) {
        final int firstByte = in.readUnsignedByte();
        final int typeNum = (firstByte >> 4) & 0x3; //bits 2-4

        assert (firstByte >> 7) == 1 : "bad packet form";
        assert ((firstByte >> 6) & 0x1) == 1 : "bad fixed bit";

        type = Type.values()[typeNum];
        meta = (byte) (firstByte & 0xF); //bits 4-8
        version = in.readInt();
        sourceID = new ConnectionID(in);
        destID = new ConnectionID(in);
        check();
    }

    LongHeader(Type type, byte meta, int version, ConnectionID sourceID, ConnectionID destID) {
        this.type = type;
        this.meta = meta;
        this.version = version;
        this.sourceID = sourceID;
        this.destID = destID;
        check();
    }

    public int length() {
        return 1 + 4 + sourceID.length() + destID.length();
    }

    public void check() {
        assert (meta >>> 4) == 0 : "bad packet meta";
    }

    public boolean isLong() {
        return true;
    }

    public ConnectionID getDestID() {
        return destID;
    }

    public String toString() {
        return  "LongHeader{" + longHeaderString() + '}';
    }

    String longHeaderString() {
        return  "type=" + type +
                ", meta=" + meta +
                ", version=" + ByteBufUtil.hexDump(Unpooled.buffer().writeInt(version)) +
                ", sourceID=" + sourceID +
                ", destID=" + destID;
    }

    void writeLongHeader(ByteBuf out) {
        check();
        out.writeByte(
                (1 << 7) | //header form: long
                (1 << 6) | //fixed bit
                (type.ordinal() << 4) |
                meta
        );
        out.writeInt(version);
        sourceID.write(out);
        destID.write(out);
    }

    public enum Type {
        INITIAL(InitialHeader::new),
        ZERO_RTT(ZeroRTTHeader::new),
        HANDSHAKE(HandshakeHeader::new),
        RETRY(RetryHeader::new);

        protected final Function<ByteBuf, LongHeader> cons;

        Type(Function<ByteBuf, LongHeader> cons) {
            this.cons = cons;
        }

        public static Type random() {
            return values()[QUICRandom.nextNibble() % values().length];
        }
    }
}
