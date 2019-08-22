package com.colingodsey.quic.packet;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.packet.components.Header;

public interface Packet {
    Header getHeader();

    static byte[] readBytes(ByteBuf in, int length) {
        final byte[] out = new byte[length];
        in.readBytes(out);
        return out;
    }

    static int getFixedLengthIntBytes(int value) {
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
}
