package com.colingodsey.quic.packet;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.CompositeByteBuf;
import io.netty.channel.ChannelPromise;
import io.netty.util.AbstractReferenceCounted;
import io.netty.util.ReferenceCountUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;

import com.colingodsey.quic.packet.components.ConnectionID;
import com.colingodsey.quic.packet.frame.Frame;
import com.colingodsey.quic.packet.frame.Padding;
import com.colingodsey.quic.utils.QUICRandom;
import com.colingodsey.quic.utils.Tuple;
import com.colingodsey.quic.utils.VariableInt;

public abstract class Packet extends AbstractReferenceCounted {
    List<Tuple<Frame, ChannelPromise>> frames = new ArrayList<>();
    int dataPayloadLength;
    int padding;
    ConnectionID destID;
    Type type;
    int packetNumber;
    byte packetNumberBytes;

    public abstract ByteBuf writeHeader(ByteBuf out);
    public abstract int headerLength();
    abstract int readHeader(ByteBuf in);

    public static int getTruncatedPacketNumber(long packetNumber, byte packetNumberBytes) {
        final long bytesMask = (1L << (packetNumberBytes * 8)) - 1;
        return (int) (packetNumber & bytesMask);
    }

    public static long getFullPacketNumber(long lastPacketNumber, int packetNumber, byte packetNumberBytes) {
        final int bytesMask = (1 << (packetNumberBytes * 8)) - 1;
        final long nextPacketNumber = lastPacketNumber + 1;
        return (nextPacketNumber ^ (nextPacketNumber & bytesMask)) | packetNumber;
    }

    public static Packet read(ByteBuf in) {
        final Type type = getType(in);
        final Packet packet = type.cons.get();
        packet.readData(in);
        return packet;
    }

    public static int getPacketNumber(ByteBuf in, int index, int packetNumberLength) {
        final int readerIndex = in.readerIndex();
        try {
            return readFixedLengthInt(in.readerIndex(index), packetNumberLength);
        } finally {
            in.readerIndex(readerIndex);
        }
    }

    public static Type getType(ByteBuf in) {
        final int firstByte = in.getUnsignedByte(in.readerIndex());
        assert ((firstByte >> 6) & 0x1) == 1 : "bad fixed bit";
        if ((firstByte >> 7) == 1) {
            return Type.values()[(firstByte >> 4) & 0x3];
        } else {
            return null; //short header
        }
    }

    public static int getProtectedPreHeaderLength(ByteBuf in) {
        final int readerIndex = in.readerIndex();
        final Type type = getType(in);

        try {
            assert type.needsProtection();
            in.readUnsignedByte(); //first byte
            in.skipBytes(4); //version
            in.skipBytes(in.readUnsignedByte()); //dcid
            if (!type.isShort()) { //long header
                in.skipBytes(in.readUnsignedByte()); //scid
            }
            if (type == Type.INITIAL) {
                in.skipBytes(VariableInt.readInt(in)); //token
            }
            VariableInt.readInt(in); //payload length
            return in.readerIndex() - readerIndex;
        } finally {
            in.readerIndex(readerIndex);
        }
    }

    public static int getPacketNumberBytes(ByteBuf in) {
        assert getType(in).needsProtection();
        final int firstByte = in.getUnsignedByte(in.readerIndex());
        return (firstByte & 0x3) + 1;
    }

    public ByteBuf produceHeader(ByteBufAllocator alloc) {
        final ByteBuf out = alloc.ioBuffer(64);
        writeHeader(out);
        return out;
    }

    public void write(CompositeByteBuf out) {
        final ByteBufAllocator alloc = out.alloc();
        out.addComponent(true, produceHeader(alloc));
        frames.forEach(tuple -> out.addComponent(true, tuple.getA().produce(alloc)));
        if (padding > 0) {
            out.addComponent(true, alloc.ioBuffer(padding).writeZero(padding));
        }
        assert out.readableBytes() == length();
    }

    public ByteBuf writePayload(ByteBuf out) {
        frames.forEach(tuple -> tuple.getA().write(out));
        out.writeZero(padding);
        return out;
    }

    public void padTo(int size) {
        //subtract one for possible size bytes increase and 16 for AAD
        int needsPad = size - length() - 1 - 16;
        if (needsPad > 0) {
            padding += needsPad;
        }
    }

    public int length() {
        return headerLength() + getPayloadLength();
    }

    public boolean add(Frame frame, ChannelPromise promise, int maxSize) {
        //add 1 to account for possible larger dataPayloadLength VariableInt
        if (length() + frame.length() + 1 > maxSize) {
            return false;
        }

        add(frame, promise);
        return true;
    }

    public void takeFrames(Consumer<Frame> consumer) {
        frames.forEach(tuple -> {
            consumer.accept(ReferenceCountUtil.retain(tuple.getA()));
            tuple.release();
        });
        frames.clear();
    }

    public void succeedAndRelease() {
        for (Tuple<?, ChannelPromise> tuple : frames) {
            if (tuple.getB() != null) {
                tuple.getB().trySuccess();
            }
        }
        release();
    }

    public void failAndRelease(Throwable t) {
        for (Tuple<?, ChannelPromise> tuple : frames) {
            if (tuple.getB() != null) {
                tuple.getB().tryFailure(t);
            }
        }
        release();
    }

    public void recallAndRelease(Consumer<Tuple<Frame, ChannelPromise>> consumer) {
        frames.forEach(consumer);
        frames.clear();
        release();
    }

    public Packet touch(Object hint) {
        frames.forEach(frame -> frame.touch(hint));
        return this;
    }

    public int getPayloadLength() {
        return dataPayloadLength + padding;
    }

    public int getPacketNumber() {
        return packetNumber;
    }

    public long getRealPacketNumber(long lastPacketNumber) {
        return getFullPacketNumber(lastPacketNumber, packetNumber, packetNumberBytes);
    }

    protected long getPacketNumberMask() {
        return (1 << (packetNumberBytes * 8)) - 1;
    }

    public int getPacketNumberBytes() {
        return packetNumberBytes;
    }

    public ConnectionID getDestID() {
        return destID;
    }

    public Type getType() {
        return type;
    }

    protected void readData(ByteBuf in) {
        assert frames.isEmpty();
        final int headerStart = in.readerIndex();
        final int payloadLength = readHeader(in);
        final int headerLength = in.readerIndex() - headerStart;

        dataPayloadLength = 0;
        padding = 0;
        while (getPayloadLength() < payloadLength && in.isReadable()) {
            final Frame frame = Frame.read(in, type);
            if (frame instanceof Padding) {
                padding += 1;
            } else {
                add(frame, null);
            }
        }
        padTo(payloadLength + headerLength + 1 + 16);
        assert getPayloadLength() == payloadLength;
        //assert (in.readerIndex() - (headerStart + headerLength)) == dataPayloadLength;
    }

    protected void add(Frame frame, ChannelPromise promise) {
        assert type.hasPayload();
        frames.add(Tuple.create(frame, promise));
        dataPayloadLength += frame.length();
    }

    protected void deallocate() {
        frames.forEach(Tuple::release);
        frames.clear();
    }

    public enum Type {
        INITIAL(InitialPacket::newEmpty),
        ZERO_RTT(ZeroRTTPacket::newEmpty),
        HANDSHAKE(HandshakePacket::newEmpty),
        RETRY(RetryPacket::newEmpty),
        ONE_RTT(OneRTTPacket::newEmpty);

        final Supplier<Packet> cons;

        Type(Supplier<Packet> cons) {
            this.cons = cons;
        }

        public static Type randomLong() {
            return values()[QUICRandom.nextNibble() % 4];
        }

        public boolean hasPayload() {
            switch (this) {
                case ZERO_RTT:
                case INITIAL:
                case HANDSHAKE:
                case ONE_RTT:
                    return true;
                default:
                    return false;
            }
        }

        public boolean needsProtection() {
            return this != RETRY;
        }

        public boolean isShort() {
            return this == ONE_RTT;
        }

        public int firstByteProtectionMask() {
            return isShort() ? 0x1F : 0xF;
        }
    }

    public interface Config {
        byte getPacketNumberBytes();
        int getVersion();
        ConnectionID getSourceID();
        ConnectionID getDestID();
        byte[] getToken(); //TODO: Token
    }

    static byte getFixedLengthIntBytes(int value) {
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

    static void writeFixedLengthInt(long value, int bytes, ByteBuf out) {
        final int iValue = (int) (value & 0xFFFFFFFF);
        switch (bytes) {
            case 1:
                out.writeByte(iValue);
                break;
            case 2:
                out.writeShort(iValue);
                break;
            case 3:
                out.writeMedium(iValue);
                break;
            case 4:
                out.writeInt(iValue);
                break;
            default:
                throw new IllegalArgumentException("Cannot writeHeader fixed length int with size: " + bytes);
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

    static byte[] readBytes(ByteBuf in, int length) {
        final byte[] out = new byte[length];
        in.readBytes(out);
        return out;
    }
}
