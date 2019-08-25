package com.colingodsey.quic.packet.frames;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.packet.components.LongHeader;
import com.colingodsey.quic.utils.VariableInt;

public class Crypto implements Frame, Frame.Initial, Frame.Handshake {
    public static final int PACKET_ID = 0x06;

    public final int offset;
    public final byte[] payload;
    private final LongHeader.Type level;

    public Crypto(ByteBuf in, LongHeader.Type level) {
        Frame.verifyPacketId(in, PACKET_ID);
        offset = VariableInt.readInt(in);
        payload = new byte[VariableInt.readInt(in)];
        in.readBytes(payload);
        this.level = level;
    }

    public Crypto(byte[] payload, int offset, LongHeader.Type level) {
        this.offset = offset;
        this.payload = payload;
        this.level = level;
    }

    public void write(ByteBuf out) {
        VariableInt.write(PACKET_ID, out);
        VariableInt.write(offset, out);
        VariableInt.write(payload.length, out);
        out.writeBytes(payload);
    }

    public LongHeader.Type getLevel() {
        return level;
    }
}
