package com.colingodsey.quic.pipeline;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageCodec;

import java.util.List;

import com.colingodsey.quic.QUIC;
import com.colingodsey.quic.packet.frame.Stream;
import com.colingodsey.quic.pipeline.component.FrameOrdering;

public class StreamOrdering extends MessageToMessageCodec<Stream, Stream> {
    protected FrameOrdering<Stream> inQueue = new FrameOrdering<>();
    protected long outOffset = 0;

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) {
        inQueue.clear();
    }

    protected void encode(ChannelHandlerContext ctx, Stream msg, List<Object> out) {
        assert msg.getOffset() == -1;
        outOffset = msg.splitAndOrder(outOffset,
                QUIC.config(ctx).getFrameSplitSize(), x -> out.add(x));
    }

    protected void decode(ChannelHandlerContext ctx, Stream msg, List<Object> out) {
        inQueue.process(msg, x -> out.add(x));
    }
}
