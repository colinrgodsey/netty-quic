package com.colingodsey.quic.crypto.pipeline;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotEquals;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPromise;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.nio.NioDatagramChannel;

import java.net.InetSocketAddress;

import com.colingodsey.quic.QUIC;
import com.colingodsey.quic.channel.DatagramChannelProxy;
import com.colingodsey.quic.utils.TestSSLContext;

import org.junit.Test;

public class JSSEHandlerTest {
    final EventLoopGroup ioGroup = new NioEventLoopGroup();
    final InetSocketAddress localhost = new InetSocketAddress("localhost", 31745);

    @Test
    public void rawHandshake() throws Exception {
        Channel server = new Bootstrap()
        .group(ioGroup)
        .channelFactory(() -> new DatagramChannelProxy(NioDatagramChannel.class))
        .handler(new ChannelInitializer<Channel>() {
            protected void initChannel(Channel ch) throws Exception {
                ch.pipeline()
                .addLast(new ChannelDuplexHandler() {
                    InetSocketAddress sender;

                    @Override
                    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                        if (msg instanceof DatagramPacket) {
                            sender = ((DatagramPacket) msg).sender();
                            msg = ((DatagramPacket) msg).content();
                        }
                        ctx.fireChannelRead(msg);
                    }

                    @Override
                    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
                        if (msg instanceof ByteBuf) {
                            msg = new DatagramPacket((ByteBuf) msg, sender);
                        }
                        ctx.write(msg, promise);
                    }
                })
                .addLast(new JSSEHandler(true, TestSSLContext.sslContext));
            }
        }).bind(localhost).sync().channel();

        Channel client = new Bootstrap()
        .group(ioGroup)
        .channelFactory(() -> new DatagramChannelProxy(NioDatagramChannel.class))
        .handler(new ChannelInitializer<Channel>() {
            protected void initChannel(Channel ch) throws Exception {
                ch.pipeline()
                .addLast(new ChannelDuplexHandler() {
                    @Override
                    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                        if (msg instanceof DatagramPacket) {
                            msg = ((DatagramPacket) msg).content();
                        }
                        ctx.fireChannelRead(msg);
                    }
                })
                .addLast(new JSSEHandler(false, TestSSLContext.sslContext));
            }
        }).connect(localhost).sync().channel();

        //normally fired elsewhere
        //server.pipeline().fireChannelActive();
        //client.pipeline().fireChannelActive();

        try {
            int maxS = 10;
            while (QUIC.config(client).getMasterContext() == null || QUIC.config(server).getMasterContext() == null) {
                if (maxS-- <= 0) {
                    throw new RuntimeException("timeout getting handshake keys");
                }
                Thread.sleep(1000);
            }

            assertNotNull(QUIC.config(client).getHandshakeContext());
            assertNotNull(QUIC.config(server).getHandshakeContext());
        } finally {
            server.close().sync();
            client.close().sync();
        }
    }
}
