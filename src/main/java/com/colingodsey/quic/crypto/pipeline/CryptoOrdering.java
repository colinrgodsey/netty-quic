package com.colingodsey.quic.crypto.pipeline;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageCodec;

import java.util.List;

import com.colingodsey.quic.QUIC;
import com.colingodsey.quic.packet.frame.Crypto;
import com.colingodsey.quic.pipeline.component.FrameOrdering;

public class CryptoOrdering extends MessageToMessageCodec<Crypto, Crypto> {
    protected FrameOrdering<Crypto> inQueue = new FrameOrdering<>();
    protected long outOffset = 0;

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) {
        inQueue.clear();
    }

    protected void encode(ChannelHandlerContext ctx, Crypto msg, List<Object> out) {
        assert msg.getOffset() == -1;
        outOffset = msg.splitAndOrder(outOffset,
                QUIC.config(ctx).getFrameSplitSize(), x -> out.add(x));
    }

    protected void decode(ChannelHandlerContext ctx, Crypto msg, List<Object> out) {
        inQueue.process(msg, x -> out.add(x));
    }
}
