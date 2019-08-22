package com.colingodsey.quic.packet;

import io.netty.buffer.ByteBuf;
import io.netty.util.AbstractReferenceCounted;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.ReferenceCounted;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.colingodsey.quic.packet.components.ConnectionID;
import com.colingodsey.quic.packet.components.Header;
import com.colingodsey.quic.packet.components.LongHeader;
import com.colingodsey.quic.packet.components.LongHeader.Type;
import com.colingodsey.quic.packet.frames.Frame;
import com.colingodsey.quic.utils.VariableInt;

public class Handshake extends AbstractReferenceCounted implements Packet {
    final LongHeader header;
    final int packetNumber;
    final List<Frame> frames = new ArrayList<>();

    public Handshake(LongHeader header, ByteBuf in) {
        assert header.type == Type.HANDSHAKE;
        this.header = header;
        final int payloadLength = VariableInt.readInt(in);
        packetNumber = Packet.readFixedLengthInt(in, getPacketNumberBytes());
        final ByteBuf tmpBuf = in.readSlice(payloadLength);
        while (tmpBuf.isReadable()) {
            frames.add(Frame.readFrame(tmpBuf));
        }
    }

    public Handshake(int version, int packetNumber, Collection<Frame> frames,
            ConnectionID sourceID, ConnectionID destID) {
        final byte packetNumberBytes = (byte) (Packet.getFixedLengthIntBytes(packetNumber) - 1);
        this.header = new LongHeader(Type.HANDSHAKE, packetNumberBytes, version, sourceID, destID);
        this.packetNumber = packetNumber;
        this.frames.addAll(frames);
    }

    public void write(ByteBuf out) {
        final ByteBuf tmpBuf = out.alloc().ioBuffer(1490);
        try {
            frames.forEach(frame -> frame.write(tmpBuf));

            header.write(out);
            VariableInt.write(tmpBuf.readableBytes(), out);
            Packet.writeFixedLengthInt(packetNumber, getPacketNumberBytes(), out);
            out.writeBytes(tmpBuf);
        } finally {
            tmpBuf.release();
        }
    }

    public int getPacketNumberBytes() {
        return header.header + 1;
    }

    protected void deallocate() {
        frames.forEach(ReferenceCountUtil::safeRelease);
        frames.clear();
    }

    public ReferenceCounted touch(Object hint) {
        frames.forEach(frame -> ReferenceCountUtil.touch(frame, hint));
        return this;
    }

    public Header getHeader() {
        return header;
    }
}
