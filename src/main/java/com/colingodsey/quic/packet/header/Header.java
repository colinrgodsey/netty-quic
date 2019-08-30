package com.colingodsey.quic.packet.header;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.packet.components.ConnectionID;
import com.colingodsey.quic.utils.VariableInt;

public abstract class Header {
    public static Header read(ByteBuf in) {
        final int firstByte = in.getUnsignedByte(in.readerIndex());
        if ((firstByte >>> 7) != 0) {
            return LongHeader.read(in);
        } else {
            return new ShortHeader(in);
        }
    }

    public static LongHeader.Type getType(ByteBuf in) {
        final int firstByte = in.getUnsignedByte(in.readerIndex());
        assert ((firstByte >> 6) & 0x1) == 1 : "bad fixed bit";
        if ((firstByte >> 7) == 1) {
            return LongHeader.Type.values()[(firstByte >> 4) & 0x3];
        } else {
            return null; //short header
        }
    }

    public static boolean needsHeaderProtection(ByteBuf in) {
        return getType(in) != LongHeader.Type.RETRY;
    }

    public static int getHeaderLength(ByteBuf in, boolean withPacketNumber) {
        final int readerIndex = in.readerIndex();
        final LongHeader.Type type = getType(in);
        final int firstByte = in.readUnsignedByte();
        in.skipBytes(4); //version
        in.skipBytes(in.readUnsignedByte()); //dcid
        if (type != null) { //long header
            in.skipBytes(in.readUnsignedByte()); //scid
        }
        if (type == LongHeader.Type.INITIAL) {
            in.skipBytes(VariableInt.readInt(in)); //token
        }
        VariableInt.readInt(in); //payload length
        if (withPacketNumber) {
            in.skipBytes((firstByte & 0x3) + 1);
        }
        final int length = in.readerIndex() - readerIndex;
        in.readerIndex(readerIndex);
        return length;
    }

    public static int getPacketNumberBytes(ByteBuf in) {
        final int firstByte = in.getUnsignedByte(in.readerIndex());
        return (firstByte & 0x3) + 1;
    }

    public abstract void write(ByteBuf out);
    public abstract ConnectionID getDestID();
    public abstract int getPayloadLength();
    public abstract int getPacketNumber();
    public abstract int getPacketNumberBytes();
    public abstract boolean isLong();

    static byte getFixedLengthIntBytes(int value) {
        if ((value >>> 8) == 0) {
            return 1;
        } else if ((value >>> 16) == 0) {
            return 2;
        } else if ((value >>> 24) == 0) {
            return 3;
        } else {
            return 4;
        }
    }

    static void writeFixedLengthInt(int value, int bytes, ByteBuf out) {
        switch (bytes) {
            case 1:
                out.writeByte(value);
                break;
            case 2:
                out.writeShort(value);
                break;
            case 3:
                out.writeMedium(value);
                break;
            case 4:
                out.writeInt(value);
                break;
            default:
                throw new IllegalArgumentException("Cannot write fixed length int with size: " + bytes);
        }
    }

    static int readFixedLengthInt(ByteBuf in, int bytes) {
        switch (bytes) {
            case 1:
                return in.readUnsignedByte();
            case 2:
                return in.readUnsignedShort();
            case 3:
                return in.readUnsignedMedium();
            case 4:
                return in.readInt();
            default:
                throw new IllegalArgumentException("Cannot read fixed length int with size: " + bytes);
        }
    }

    static byte[] readBytes(ByteBuf in, int length) {
        final byte[] out = new byte[length];
        in.readBytes(out);
        return out;
    }
}
