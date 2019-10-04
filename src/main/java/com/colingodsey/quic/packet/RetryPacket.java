package com.colingodsey.quic.packet;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.packet.component.ConnectionID;
import com.colingodsey.quic.utils.QUICRandom;
import com.colingodsey.quic.utils.VariableInt;

public class RetryPacket extends LongHeaderPacket {
    ConnectionID originalDestID;
    byte[] token;

    private RetryPacket() {}

    public static RetryPacket read(ByteBuf in) {
        final RetryPacket out = new RetryPacket();
        out.readData(in);
        return out;
    }

    public static RetryPacket create(Packet.Config config) {
        final RetryPacket out = newEmpty();
        out.type = Type.RETRY;
        out.version = config.getVersion();
        out.sourceID = config.getSourceID();
        out.destID = config.getDestID();
        out.token = config.getToken();
        out.packetNumberBytes = QUICRandom.nextNibble();
        return out;
    }

    static RetryPacket newEmpty() {
        return new RetryPacket();
    }

    @Override
    public int readHeader(ByteBuf in) {
        super.readHeader(in);
        originalDestID = ConnectionID.read(in);
        token = readBytes(in, VariableInt.readInt(in));
        return 0;
    }

    @Override
    public ByteBuf writeHeader(ByteBuf out) {
        final int startIndex = out.readerIndex();
        super.writeHeader(out);
        originalDestID.write(out);
        VariableInt.write(token.length, out).writeBytes(token);
        assert (out.readerIndex() - startIndex) == headerLength();
        return out;
    }

    @Override
    public int headerLength() {
        return super.headerLength() +
                originalDestID.length() +
                VariableInt.length(token.length) + token.length;
    }
}
