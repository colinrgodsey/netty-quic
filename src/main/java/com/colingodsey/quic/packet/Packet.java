package com.colingodsey.quic.packet;

import io.netty.buffer.ByteBuf;
import io.netty.util.AbstractReferenceCounted;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.ReferenceCounted;

import com.colingodsey.quic.packet.header.Header;

public final class Packet extends AbstractReferenceCounted {
    private final Header header;
    private final ByteBuf payload;

    public Packet(Header header, ByteBuf payload) {
        //assert header.getPayloadLength() == payload.readableBytes();
        this.header = header;
        this.payload = payload;
    }

    public Header getHeader() {
        return header;
    }

    public ByteBuf getPayload() {
        return payload;
    }

    /*public int length() {
        return header.getLength() + payload.readableBytes();
    }*/

    public ReferenceCounted touch(Object hint) {
        payload.touch(hint);
        ReferenceCountUtil.touch(header, hint);
        return this;
    }

    protected void deallocate() {
        payload.release();
        ReferenceCountUtil.release(header);
    }
}
