package com.colingodsey.quic.packet;

import io.netty.buffer.ByteBuf;

import java.math.BigInteger;

import com.colingodsey.quic.packet.components.LongHeader;
import com.colingodsey.quic.packet.components.LongHeader.Type;
import com.colingodsey.quic.utils.QUICRandom;

public class Retry implements Packet {
    final LongHeader header;
    BigInteger originalDestID;
    final byte[] token;

    public Retry(LongHeader header, ByteBuf in) {
        assert header.type == Type.RETRY;
        this.header = header;
        originalDestID = Packet.readID(in);
        token = Packet.readBytes(in, in.readableBytes());
    }

    public Retry(int version, byte[] token,
            BigInteger sourceID, BigInteger destID, BigInteger originalDestID) {
        this.header = new LongHeader(Type.RETRY, QUICRandom.nextNibble(), version, sourceID, destID);
        this.originalDestID = originalDestID;
        this.token = token;
    }

    public void write(ByteBuf out) {
        header.write(out);
        Packet.writeID(originalDestID, out);
        out.writeBytes(token);
    }
}
