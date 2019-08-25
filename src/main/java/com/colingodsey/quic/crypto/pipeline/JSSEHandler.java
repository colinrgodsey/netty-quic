package com.colingodsey.quic.crypto.pipeline;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

import com.colingodsey.quic.QUIC;
import com.colingodsey.quic.crypto.context.CryptoContext;
import com.colingodsey.quic.packet.components.LongHeader;
import com.colingodsey.quic.packet.components.LongHeader.Type;
import com.colingodsey.quic.packet.frames.Crypto;
import com.colingodsey.quic.utils.Utils;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

public class JSSEHandler extends ChannelInboundHandlerAdapter {
    static final ByteBuffer EMPTY_BYTEBUFFER = ByteBuffer.wrap(new byte[0]);

    final boolean isServer;
    final SSLEngine engine;

    ByteBuf inBuffer;
    ByteBuf outBuffer;
    boolean dirty = false;
    boolean helloReceived = false;
    int initialOffset = 0;
    int handshakeOffset = 0;

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
        ctx.channel().eventLoop().execute(() -> {
            ctx.fireChannelActive();
            if (!isServer) {
                processHandshake(ctx);
                maybeFlush(ctx);
            }
        });
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

    protected void produceTLSMessage(ChannelHandlerContext ctx) {
        final byte[] payload = new byte[outBuffer.readableBytes()];
        ctx.write(outBuffer.copy());
        //outBuffer.readBytes(payload);
        outBuffer.clear();

        /*if (!helloReceived) {
            ctx.write(new Crypto(payload, initialOffset, Type.INITIAL));
            initialOffset += payload.length;
        } else {
            ctx.write(new Crypto(payload, handshakeOffset, Type.HANDSHAKE));
            handshakeOffset += payload.length;
        }*/

        dirty = true;
    }

    protected void processHandshake0(ChannelHandlerContext ctx) {
        try {
            final SSLEngineResult readRes = engine.unwrap(inBuffer.nioBuffer(), EMPTY_BYTEBUFFER);
            final SSLEngineResult writeRes = engine.wrap(EMPTY_BYTEBUFFER,
                    outBuffer.nioBuffer(outBuffer.writerIndex(), outBuffer.writableBytes()));

            if (inBuffer.isReadable()) {
                helloReceived = true;
            }

            outBuffer.writerIndex(outBuffer.writerIndex() + writeRes.bytesProduced());
            inBuffer.readerIndex(inBuffer.readerIndex() + readRes.bytesConsumed());

            if (!inBuffer.isReadable()) {
                inBuffer.clear();
            }

            if (outBuffer.isReadable()) {
                produceTLSMessage(ctx);
            }

            checkKeys(ctx);
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
    }

    protected void checkKeys(ChannelHandlerContext ctx) {
        final QUIC.Config config = QUIC.config(ctx);

        SSLSession session = engine.getHandshakeSession();

        if (session == null) {
            session = engine.getSession();
        }

        try {
            if (engine instanceof org.openjsse.javax.net.ssl.SSLEngine && session != null) {
                final org.openjsse.javax.net.ssl.SSLEngine openEngine = (org.openjsse.javax.net.ssl.SSLEngine) engine;

                if (config.getHandshakeContext() == null && openEngine.getHandshakeReadSecret() != null
                        && engine.getHandshakeStatus() != HandshakeStatus.NOT_HANDSHAKING) {
                    config.setHandshakeContext(
                            CryptoContext.createKeyed(session.getCipherSuite(),
                                    openEngine.getHandshakeWriteSecret(), openEngine.getHandshakeReadSecret()));
                }

                if (config.getMasterContext() == null && openEngine.getMasterReadSecret() != null) {
                    config.setMasterContext(
                            CryptoContext.createKeyed(session.getCipherSuite(),
                                    openEngine.getMasterWriteSecret(), openEngine.getMasterReadSecret()));
                }
            }
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    protected void onHandshakeKey(ChannelHandlerContext ctx) {
        // NOOP
    }

    protected void onMasterKey(ChannelHandlerContext ctx) {
        // NOOP
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
            taskList.add(() -> checkKeys(ctx));
            ctx.channel().eventLoop().execute(() -> taskList.forEach(Runnable::run));
        }
    }
}
