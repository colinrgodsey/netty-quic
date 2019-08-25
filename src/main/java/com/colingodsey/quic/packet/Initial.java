package com.colingodsey.quic.packet;

import io.netty.buffer.ByteBuf;
import io.netty.util.AbstractReferenceCounted;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.ReferenceCounted;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.colingodsey.quic.crypto.context.CryptoContext;
import com.colingodsey.quic.packet.components.ConnectionID;
import com.colingodsey.quic.packet.components.LongHeader;
import com.colingodsey.quic.packet.components.LongHeader.Type;
import com.colingodsey.quic.packet.frames.Frame;
import com.colingodsey.quic.packet.frames.Padding;
import com.colingodsey.quic.utils.Utils;
import com.colingodsey.quic.utils.VariableInt;

public class Initial extends AbstractReferenceCounted implements Packet {
    public static final int PAD_PAYLOAD_TO = 1163;

    final LongHeader header;
    final byte[] token;
    final int packetNumber;
    final List<Frame.Initial> frames = new ArrayList<>();

    public Initial(ByteBuf in) {
        this(new LongHeader(in), in);
    }

    public Initial(LongHeader header, ByteBuf in) {
        assert header.type == Type.INITIAL;
        this.header = header;
        token = Packet.readBytes(in, VariableInt.readInt(in));
        final int payloadLength = VariableInt.readInt(in);
        packetNumber = Packet.readFixedLengthInt(in, getPacketNumberBytes());
        final ByteBuf payloadBuf = in.readSlice(Math.min(payloadLength, in.readableBytes()));
        while (payloadBuf.isReadable()) {
            final Frame.Initial frame = (Frame.Initial) Frame.readFrame(payloadBuf);
            if (!(frame instanceof Padding)) {
                frames.add(frame);
            }
        }
    }

    public Initial(int version, byte[] token, int packetNumber,
            Collection<Frame.Initial> frames, ConnectionID sourceID, ConnectionID destID) {
        final byte packetNumberBytes = (byte) (Packet.getFixedLengthIntBytes(packetNumber) - 1);
        this.header = new LongHeader(Type.INITIAL, packetNumberBytes, version, sourceID, destID);
        this.token = token;
        this.packetNumber = packetNumber;
        this.frames.addAll(frames);
    }

    public void write(ByteBuf out) {
        final ByteBuf tmpBuf = out.alloc().ioBuffer(1490);
        try {
            writePayload(tmpBuf);
            writeHeader(out, tmpBuf.readableBytes());
            out.writeBytes(tmpBuf);
        } finally {
            tmpBuf.release();
        }
    }

    public byte[] produceEncrypted(CryptoContext ctx) {
        final byte[] payloadData = Utils.createBytes(buf -> {
            writePayload(buf);
            if (buf.readableBytes() < PAD_PAYLOAD_TO) {
                buf.writeZero(PAD_PAYLOAD_TO - buf.readableBytes());
            }
        }, 1200);
        final byte[] headerData = Utils.createBytes(buf -> writeHeader(buf, payloadData.length), 128);

        final byte[] ePayloadData = ctx.encryptPayload(headerData, payloadData, packetNumber);
        final byte[] mask = ctx.headerProtectMask(ePayloadData, getPacketNumberBytes());
        final int pnOffset = headerData.length - getPacketNumberBytes();

        //encrypt flags and packet number
        headerData[0] ^= mask[0] & 0x0F;
        for (int i = 0 ; i < getPacketNumberBytes() ; i++) {
            headerData[pnOffset + i] ^= mask[1 + i];
        }

        return Utils.concat(headerData, ePayloadData);
    }

    public int getPacketNumberBytes() {
        return header.header + 1;
    }

    protected int headerLength() {
        return header.length() + 2 + token.length + 2 + getPacketNumberBytes();
    }

    protected void writeHeader(ByteBuf out, int payloadLength) {
        header.write(out);
        VariableInt.write(token.length, out);
        out.writeBytes(token);
        VariableInt.write(payloadLength, out);
        Packet.writeFixedLengthInt(packetNumber, getPacketNumberBytes(), out);
    }

    protected void writePayload(ByteBuf out) {
        frames.forEach(frame -> frame.write(out));
    }

    protected void deallocate() {
        frames.forEach(ReferenceCountUtil::safeRelease);
        frames.clear();
    }

    public ReferenceCounted touch(Object hint) {
        frames.forEach(frame -> ReferenceCountUtil.touch(frame, hint));
        return this;
    }

    public LongHeader getHeader() {
        return header;
    }
}
