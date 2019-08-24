package com.colingodsey.quic.crypto.pipeline;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;

public class JSSEHandler extends ChannelInboundHandlerAdapter {
    static final ByteBuffer EMPTY_BYTEBUFFER = ByteBuffer.wrap(new byte[0]);

    final boolean isServer;
    final SSLEngine engine;

    ByteBuf inBuffer;
    ByteBuf outBuffer;
    boolean dirty = false;

    public JSSEHandler(boolean isServer, SSLContext context) {
        this.isServer = isServer;
        engine = context.createSSLEngine();
        engine.setUseClientMode(!isServer);
        if (isServer) {
            engine.setWantClientAuth(true);
        }
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
        inBuffer = newHandshakeBuffer(ctx);
        outBuffer = newHandshakeBuffer(ctx);
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        ctx.fireChannelActive();
        if (!isServer) {
            processHandshake(ctx);
            maybeFlush(ctx);
        }
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) throws Exception {
        if (inBuffer != null) {
            inBuffer.release();
        }
        if (outBuffer != null) {
            outBuffer.release();
        }
        inBuffer = outBuffer = null;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof ByteBuf) {
            try {
                inBuffer.writeBytes((ByteBuf) msg);
            } finally {
                ReferenceCountUtil.release(msg);
            }
        } else {
            ctx.fireChannelRead(msg);
        }
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) throws Exception {
        processHandshake(ctx);
        ctx.fireChannelReadComplete();
        maybeFlush(ctx);
    }

    protected ByteBuf newHandshakeBuffer(ChannelHandlerContext ctx) {
        return ctx.alloc().ioBuffer(engine.getSession().getPacketBufferSize());
    }

    protected void processHandshake0(ChannelHandlerContext ctx) {
        try {
            final SSLEngineResult readRes = engine.unwrap(inBuffer.nioBuffer(), EMPTY_BYTEBUFFER);
            final SSLEngineResult writeRes = engine.wrap(EMPTY_BYTEBUFFER,
                    outBuffer.nioBuffer(outBuffer.writerIndex(), outBuffer.writableBytes()));

            outBuffer.writerIndex(outBuffer.writerIndex() + writeRes.bytesProduced());
            inBuffer.readerIndex(inBuffer.readerIndex() + readRes.bytesConsumed());

            if (!inBuffer.isReadable()) {
                inBuffer.clear();
            }

            if (outBuffer.isReadable()) {
                ctx.write(outBuffer.copy());
                outBuffer.clear();
                dirty = true;
            }
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
    }

    protected boolean shouldWrap() {
        return engine.getHandshakeStatus() == HandshakeStatus.NEED_WRAP;
    }

    protected boolean shouldUnwrap() {
        return engine.getHandshakeStatus() == HandshakeStatus.NEED_UNWRAP && inBuffer.isReadable();
    }

    protected void maybeFlush(ChannelHandlerContext ctx) {
        if (dirty) {
            dirty = false;
            ctx.flush();
        }
    }

    protected void processHandshake(ChannelHandlerContext ctx) {
        processHandshake0(ctx);

        while (shouldWrap() || shouldUnwrap()) {
            processHandshake0(ctx);
        }

        if (engine.getHandshakeStatus() == HandshakeStatus.NEED_TASK) {
            final List<Runnable> taskList = new ArrayList<>();
            Runnable runnable;
            //TODO: should these go to a different event group?
            while ((runnable = engine.getDelegatedTask()) != null) {
                taskList.add(runnable);
            }
            taskList.add(() -> processHandshake(ctx));
            taskList.add(() -> maybeFlush(ctx));
            ctx.channel().eventLoop().execute(() -> taskList.forEach(Runnable::run));
        }

        if(engine.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING) {
            System.out.println("Finished! server: " + isServer);
        }
    }
}
