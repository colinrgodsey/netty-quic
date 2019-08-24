package com.colingodsey.quic.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.util.Arrays;

import com.colingodsey.quic.crypto.context.TLS_AES_128_GCM_SHA256;

import com.colingodsey.quic.utils.TestSSLContext;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLSession;

import org.junit.Test;
import org.openjsse.javax.net.ssl.SSLParameters;

public class CryptoTest {
    @Test
    public void jvmTest() {
        SSLEngine engine = TestSSLContext.sslContext.createSSLEngine();
        System.out.println(Arrays.asList(engine.getEnabledCipherSuites()));
        System.out.println(Arrays.asList(engine.getEnabledProtocols()));

        //TSL 1.3 is java 11 only
        assertTrue("This JVM does not support TLSv1.3",
                Arrays.asList(engine.getEnabledCipherSuites()).contains("TLS_AES_128_GCM_SHA256"));
    }

    void setQuicParam(SSLEngine engine, String name, long value) {
        SSLParameters params = (SSLParameters) engine.getSSLParameters();
        params.setQuicTransParam(name, value);
        engine.setSSLParameters(params);
    }

    @Test
    public void rawHandshake() throws Exception {
        SSLEngine client = TestSSLContext.sslContext.createSSLEngine("dummy.example.com", 80);
        SSLEngine server = TestSSLContext.sslContext.createSSLEngine();

        client.setUseClientMode(true);
        server.setUseClientMode(false);
        server.setWantClientAuth(true);

        setQuicParam(server, "initial_max_streams_bidi", 10);
        setQuicParam(server, "initial_max_stream_data_uni", 1000);
        setQuicParam(client, "initial_max_streams_uni", 10);

        boolean dataDone = false;
        int itrs = 200;

        final SSLSession clientSession = client.getSession();
        final int appBufferMax = clientSession.getApplicationBufferSize();
        final int netBufferMax = clientSession.getPacketBufferSize();

        clientSession.putValue("test", 1);

        final ByteBuffer clientOut = ByteBuffer.wrap("Hi Server, I'm Client".getBytes());
        final ByteBuffer clientIn = ByteBuffer.allocateDirect(appBufferMax + 64);
        final ByteBuffer cToS = ByteBuffer.allocateDirect(netBufferMax);
        final ByteBuffer serverOut = ByteBuffer.wrap("Hello Client, I'm Server".getBytes());
        final ByteBuffer serverIn = ByteBuffer.allocateDirect(appBufferMax + 64);
        final ByteBuffer sToC = ByteBuffer.allocateDirect(netBufferMax);

        while (!isEngineClosed(client) || !isEngineClosed(server)) {
            if (itrs-- < 0) {
                throw new RuntimeException("Too many iterations. Server outbound done: "
                        + server.isOutboundDone() + ", inbound done: " + server.isInboundDone());
            }

            System.out.println("===========");
            int clientOutBytes = clientOut.remaining();
            int serverOutBytes = serverOut.remaining();
            checkStatus(client.wrap(clientOut, cToS), client);
            checkStatus(server.wrap(serverOut, sToC), server);

            if (clientOutBytes != clientOut.remaining()) {
                System.out.println("Wrote client data bytes: " + (clientOutBytes - clientOut.remaining()));
            }
            if (serverOutBytes != serverOut.remaining()) {
                System.out.println("Wrote server data bytes: " + (serverOutBytes - serverOut.remaining()));
            }

            cToS.flip();
            sToC.flip();

            System.out.println("-----");

            checkStatus(client.unwrap(sToC, clientIn), client);
            checkStatus(server.unwrap(cToS, serverIn), server);

            cToS.compact();
            sToC.compact();

            if (!dataDone && (clientOut.limit() == serverIn.position()) &&
                    (serverOut.limit() == clientIn.position())) {
                checkTransfer(serverOut, clientIn);
                checkTransfer(clientOut, serverIn);

                System.out.println("\tClosing clientEngine's *OUTBOUND*...");
                client.closeOutbound();
                dataDone = true;
            }

            if (server.isInboundDone() && !server.isOutboundDone()) {
                System.out.println("\tClosing serverEngine's *OUTBOUND*...");
                server.closeOutbound();
            }
        }

        assertTrue(client.isOutboundDone());
        assertTrue(server.isInboundDone());
        assertEquals("TLS_AES_128_GCM_SHA256", client.getSession().getCipherSuite());

        new TLS_AES_128_GCM_SHA256((SecretKey) client.getSession().getValue("tls13_handshake_secret"));
        new TLS_AES_128_GCM_SHA256((SecretKey) server.getSession().getValue("tls13_handshake_secret"));

        new TLS_AES_128_GCM_SHA256((SecretKey) client.getSession().getValue("tls13_master_secret"));
        new TLS_AES_128_GCM_SHA256((SecretKey) server.getSession().getValue("tls13_master_secret"));

        System.out.println("Client session values: ");
        for (String key : client.getSession().getValueNames()) {
            System.out.println("  " + key + ": " + client.getSession().getValue(key));
        }

        System.out.println("\nServer session values: ");
        for (String key : server.getSession().getValueNames()) {
            System.out.println("  " + key + ": " + server.getSession().getValue(key));
        }
    }

    private static void checkTransfer(ByteBuffer a, ByteBuffer b)
            throws Exception {
        a.flip();
        b.flip();

        if (!a.equals(b)) {
            throw new Exception("Data didn't transfer cleanly");
        } else {
            System.out.println("\tData transferred cleanly");
        }

        a.position(a.limit());
        b.position(b.limit());
        a.limit(a.capacity());
        b.limit(b.capacity());
    }

    private static void runDelegatedTasks(SSLEngineResult result, SSLEngine engine) throws Exception {
        if (result.getHandshakeStatus() == HandshakeStatus.NEED_TASK) {
            Runnable runnable;
            while ((runnable = engine.getDelegatedTask()) != null) {
                System.out.println("\trunning delegated task, client: " + engine.getUseClientMode());
                runnable.run();
            }
            HandshakeStatus hsStatus = engine.getHandshakeStatus();
            if (hsStatus == HandshakeStatus.NEED_TASK) {
                throw new Exception("handshake shouldn't need additional tasks");
            }
            assertTrue(hsStatus == HandshakeStatus.NEED_WRAP);
        }
    }

    private static boolean isEngineClosed(SSLEngine engine) {
        return engine.isOutboundDone() && engine.isInboundDone();
    }

    private static void checkStatus(SSLEngineResult res, SSLEngine engine) throws Exception {
        runDelegatedTasks(res, engine);
    }
}
