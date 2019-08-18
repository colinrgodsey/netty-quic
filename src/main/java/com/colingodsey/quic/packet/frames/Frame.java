package com.colingodsey.quic.packet.frames;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.utils.VariableInt;

public interface Frame {
    static Frame readFrame(ByteBuf in) {
        final int readerIndex = in.readerIndex();
        final int packetId = VariableInt.readInt(in);
        in.readerIndex(readerIndex);

        switch (packetId) {
            case Padding.PACKET_ID: // PADDING
                return Padding.read(in);
            case 0x01: // PING
                return Ping.read(in);
            case 0x02: // ACK
            case 0x03:
            case 0x04: // RESET_STREAM
            case 0x05: // STOP_SENDING
            case 0x06: // CRYPTO
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
        }
        return null;
    }

    void write(ByteBuf out);
}
