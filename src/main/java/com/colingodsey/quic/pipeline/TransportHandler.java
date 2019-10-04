package com.colingodsey.quic.pipeline;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;

import com.colingodsey.quic.packet.frame.Frame;

public class TransportHandler extends SimpleChannelInboundHandler<Frame> {
    protected void channelRead0(ChannelHandlerContext ctx, Frame msg) throws Exception {

    }
}
