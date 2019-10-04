package com.colingodsey.quic.packet.frame;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.utils.VariableInt;

public abstract class StreamsBlocked implements Frame {
    public static final int PACKET_ID = 0x16;

    final long streamLimit;

    private StreamsBlocked(ByteBuf in) {
        streamLimit = VariableInt.read(in);
    }

    private StreamsBlocked(long streamLimit) {
        this.streamLimit = streamLimit;
    }

    public static StreamsBlocked read(ByteBuf in) {
        switch (VariableInt.readInt(in)) {
            case PACKET_ID:
                return new BiDi(in);
            case PACKET_ID + 1:
                return new Uni(in);
        }
        throw new IllegalArgumentException();
    }

    public long getStreamLimit() {
        return streamLimit;
    }

    public int length() {
        return 1 + VariableInt.length(streamLimit);
    }

    public static class BiDi extends StreamsBlocked {
        public BiDi(long streamLimit) {
            super(streamLimit);
        }

        public BiDi(ByteBuf in) {
            super(in);
        }

        public void write(ByteBuf out) {
            VariableInt.write(PACKET_ID, out);
            VariableInt.write(streamLimit, out);
        }
    }

    public static class Uni extends StreamsBlocked {
        public Uni(long streamLimit) {
            super(streamLimit);
        }

        public Uni(ByteBuf in) {
            super(in);
        }

        public void write(ByteBuf out) {
            VariableInt.write(PACKET_ID + 1, out);
            VariableInt.write(streamLimit, out);
        }
    }
}
