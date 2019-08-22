package com.colingodsey.quic.packet;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.packet.components.ConnectionID;
import com.colingodsey.quic.packet.components.Header;
import com.colingodsey.quic.packet.components.LongHeader;
import com.colingodsey.quic.packet.components.LongHeader.Type;
import com.colingodsey.quic.utils.QUICRandom;

public class Retry implements Packet {
    final LongHeader header;
    ConnectionID originalDestID;
    final byte[] token;

    public Retry(LongHeader header, ByteBuf in) {
        assert header.type == Type.RETRY;
        this.header = header;
        originalDestID = new ConnectionID(in);
        token = Packet.readBytes(in, in.readableBytes());
    }

    public Retry(int version, byte[] token,
            ConnectionID sourceID, ConnectionID destID, ConnectionID originalDestID) {
        this.header = new LongHeader(Type.RETRY, QUICRandom.nextNibble(), version, sourceID, destID);
        this.originalDestID = originalDestID;
        this.token = token;
    }

    public void write(ByteBuf out) {
        header.write(out);
        originalDestID.write(out);
        out.writeBytes(token);
    }

    public Header getHeader() {
        return header;
    }
}
