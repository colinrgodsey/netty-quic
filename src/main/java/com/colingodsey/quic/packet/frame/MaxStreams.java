package com.colingodsey.quic.packet.frame;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.utils.VariableInt;

public abstract class MaxStreams implements Frame {
    public static final int PACKET_ID = 0x12;

    final long maxStreams;

    private MaxStreams(ByteBuf in) {
        maxStreams = VariableInt.read(in);
    }

    private MaxStreams(long maxStreams) {
        this.maxStreams = maxStreams;
    }

    public static MaxStreams read(ByteBuf in) {
        switch (VariableInt.readInt(in)) {
            case PACKET_ID:
                return new BiDi(in);
            case PACKET_ID + 1:
                return new Uni(in);
        }
        throw new IllegalArgumentException();
    }

    public long getMaxStreams() {
        return maxStreams;
    }

    public int length() {
        return 1 + VariableInt.length(maxStreams);
    }

    public static class BiDi extends MaxStreams {
        public BiDi(long maxStreams) {
            super(maxStreams);
        }

        public BiDi(ByteBuf in) {
            super(in);
        }

        public void write(ByteBuf out) {
            VariableInt.write(PACKET_ID, out);
            VariableInt.write(maxStreams, out);
        }
    }

    public static class Uni extends MaxStreams {
        public Uni(long maxStreams) {
            super(maxStreams);
        }

        public Uni(ByteBuf in) {
            super(in);
        }

        public void write(ByteBuf out) {
            VariableInt.write(PACKET_ID + 1, out);
            VariableInt.write(maxStreams, out);
        }
    }
}
