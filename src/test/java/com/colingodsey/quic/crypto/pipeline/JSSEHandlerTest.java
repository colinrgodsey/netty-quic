package com.colingodsey.quic.crypto.pipeline;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import io.netty.channel.embedded.QUICTestChannel;

import com.colingodsey.quic.QUIC;
import com.colingodsey.quic.packet.components.LongHeader.Type;
import com.colingodsey.quic.packet.frame.Crypto;
import com.colingodsey.quic.utils.TestFrameCodec;
import com.colingodsey.quic.utils.TestSSLContext;

import org.junit.Test;

public class JSSEHandlerTest {
    @Test
    public void testHandshakeLevels() {
        QUICTestChannel client = new QUICTestChannel(new JSSEHandler(false, TestSSLContext.sslContext));
        QUICTestChannel server = new QUICTestChannel(new JSSEHandler(true, TestSSLContext.sslContext));

        testHandshake(client, server);

        assertNotNull(QUIC.config(server).getMasterContext());
        assertNotNull(QUIC.config(client).getMasterContext());
        System.gc();
    }

    @Test
    public void testCryptoOrdering() {
        QUICTestChannel client = new QUICTestChannel(
                cfg -> cfg.setFrameSplitSize(31),
                new TestFrameCodec(),
                new CryptoOrdering(),
                new JSSEHandler(false, TestSSLContext.sslContext)
        );
        QUICTestChannel server = new QUICTestChannel(
                cfg -> cfg.setFrameSplitSize(37),
                new TestFrameCodec(),
                new CryptoOrdering(),
                new JSSEHandler(true, TestSSLContext.sslContext)
        );

        flushUntilEmpty(client, server);

        assertNotNull(QUIC.config(server).getMasterContext());
        assertNotNull(QUIC.config(client).getMasterContext());
        System.gc();
    }

    void checkForward(QUICTestChannel from, Type type, QUICTestChannel to) {
        from.runPendingTasks();
        to.runPendingTasks();

        Crypto msg = from.readOutbound();
        assertEquals(type, msg.getLevel());
        to.writeOneInbound(msg);
        to.flushInbound();

        from.runPendingTasks();
        to.runPendingTasks();
    }

    void forward(QUICTestChannel from, QUICTestChannel to) {
        Object msg = from.readOutbound();
        if (msg != null) {
            to.writeOneInbound(msg);
            to.flushInbound();
        }

        from.runPendingTasks();
        to.runPendingTasks();
    }

    void flushUntilEmpty(QUICTestChannel a, QUICTestChannel b) {
        while (!a.outboundMessages().isEmpty() || !b.outboundMessages().isEmpty()) {
            forward(a, b);
            forward(b, a);
        }
    }

    void testHandshake(QUICTestChannel client, QUICTestChannel server) {
        checkForward(client, Type.INITIAL, server); //ClientHello
        checkForward(server, Type.INITIAL, client); //ServerHello

        assertNotNull(QUIC.config(server).getHandshakeContext());
        assertNotNull(QUIC.config(client).getHandshakeContext());

        while (!server.outboundMessages().isEmpty()) {
            checkForward(server, Type.HANDSHAKE, client); //EE, CERT, CV, FIN
        }

        checkForward(client, Type.HANDSHAKE, server); //Finished
        checkForward(client, Type.HANDSHAKE, server); //NewSessionTicket
    }
}
