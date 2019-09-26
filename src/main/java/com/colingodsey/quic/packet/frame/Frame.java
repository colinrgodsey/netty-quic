package com.colingodsey.quic.packet.frame;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;

import java.util.function.Consumer;

import com.colingodsey.quic.packet.Packet;
import com.colingodsey.quic.utils.VariableInt;

public interface Frame {
    static Frame read(ByteBuf in, Packet.Type level) {
        final int readerIndex = in.readerIndex();
        final int frameId = VariableInt.readInt(in);
        in.readerIndex(readerIndex);

        switch (frameId) {
            case Padding.PACKET_ID: // PADDING
                return Padding.read(in);
            case Ping.PACKET_ID: // PING
                return Ping.read(in);
            case Ack.PACKET_ID: // ACK
            case Ack.PACKET_ID + 1:
                return new Ack(in);
            //case 0x04: // RESET_STREAM
            //case 0x05: // STOP_SENDING
            case Crypto.PACKET_ID: // CRYPTO
                return Crypto.read(in, level);
            case 0x07: // NEW_TOKEN
            case 0x08: // STREAM
            case 0x09:
            case 0x0A:
            case 0x0B:
            case 0x0C:
            case 0x0D:
            case 0x0E:
            case 0x0F:
            case 0x10: // MAX_DATA
            case 0x11: // MAX_STREAM_DATA
            case 0x12: // MAX_STREAMS
            case 0x13:
            case 0x14: // DATA_BLOCKED
            case 0x15: // STREAM_DATA_BLOCKED
            case 0x16: // STREAMS_BLOCKED
            case 0x17:
            case 0x18: // NEW_CONNECTION_ID
            case 0x19: // RETIRE_CONNECTION_ID
            case 0x1A: // PATH_CHALLENGE
            case 0x1B: // PATH_RESPONSE
            case 0x1C: // CONNECTION_CLOSE
            case 0x1D:
            default:
                throw new RuntimeException("Unknown frame ID " + frameId);
        }
    }

    static void verifyPacketId(ByteBuf in, int packetID) {
        if (VariableInt.readInt(in) != packetID) {
            throw new IllegalArgumentException("Expecting packetID: " + packetID);
        }
    }

    void write(ByteBuf out);
    int length();

    default Packet.Type getLevel() {
        return null;
    }

    default ByteBuf produce(ByteBufAllocator alloc) {
        final ByteBuf out = alloc.ioBuffer(length());
        write(out);
        return out;
    }

    interface Initial extends Frame {}
    interface Handshake extends Frame {}

    interface Orderable extends Frame {
        long getOffset();
        int getPayloadLength();
        long splitAndOrder(long offset, int maxLength, Consumer<Crypto> out);

        class Comparator implements java.util.Comparator<Frame.Orderable> {
            public static final java.util.Comparator<Frame.Orderable> INSTANCE = new Comparator();

            private Comparator() {}

            public int compare(Frame.Orderable a, Frame.Orderable b) {
                return Long.compare(a.getOffset(), b.getOffset());
            }
        }
    }
}
