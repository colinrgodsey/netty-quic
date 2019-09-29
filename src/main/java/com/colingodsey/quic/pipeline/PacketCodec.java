package com.colingodsey.quic.pipeline;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageCodec;

import java.util.List;

import com.colingodsey.quic.packet.Packet;

public class PacketCodec extends MessageToMessageCodec<ByteBuf, Packet> {
    protected void encode(ChannelHandlerContext ctx, Packet msg, List<Object> out) throws Exception {


    }

    protected void decode(ChannelHandlerContext ctx, ByteBuf msg, List<Object> out) throws Exception {

    }
}
