package com.colingodsey.quic.crypto;

import static com.colingodsey.quic.utils.Utils.h2ba;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.util.Arrays;

import com.colingodsey.quic.packet.components.ConnectionID;

import com.colingodsey.quic.utils.QUICRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;

import org.junit.Test;
import org.openjsse.javax.net.ssl.SSLParameters;

public class CryptoTest {
    final String connIDStr = "8394c8f03e515708";
    final ConnectionID connID = new ConnectionID(h2ba(connIDStr));
    final DerivedSecrets secrets = new DerivedSecrets(connID);

    final KeyManagerFactory kmf;
    final TrustManagerFactory tmf;
    final SSLContext context;
    {
        TLS.init();

        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            KeyStore ts = KeyStore.getInstance("JKS");

            char[] passphrase = "passphrase".toCharArray();

            ks.load(new FileInputStream(Thread.currentThread().getContextClassLoader().getResource("tlstest/keystore").getFile()), passphrase);
            ts.load(new FileInputStream(Thread.currentThread().getContextClassLoader().getResource("tlstest/truststore").getFile()), passphrase);

            kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, passphrase);

            tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ts);

            context = SSLContext.getInstance("TLS");
            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), QUICRandom.getSecureRandom());
        } catch (Exception e) {
            throw new RuntimeException("failed to load test materials", e);
        }
    }

    //is this example just bad?
    /*@Test
    public void initialProtectionTest2() throws Exception {
        byte[] sample = h2ba("65f354ebb400418b614f73765009c016");
        SecretKeySpec skeySpec = new SecretKeySpec(secrets.clientSecrets.hp, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

        assertArrayEquals(
                h2ba("519bd343ff"),
                Arrays.copyOf(cipher.doFinal(sample), 5));
    }*/

    @Test
    public void initialProtectionTest1() throws Exception {
        byte[] sample = h2ba("da5c83732bb0d8c945563b6ba1a57a5f");
        SecretKeySpec skeySpec = new SecretKeySpec(h2ba("3271d12d0c6e3faac0e1e8a29294146c"), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

        assertArrayEquals(
                h2ba("0ed450ec84"),
                Arrays.copyOf(cipher.doFinal(sample), 5));
    }

    @Test
    public void jvmTest() {
        SSLEngine engine = context.createSSLEngine();
        System.out.println(Arrays.asList(engine.getEnabledCipherSuites()));
        System.out.println(Arrays.asList(engine.getEnabledProtocols()));

        //TSL 1.3 is java 11 only
        assertTrue("This JVM does not support TLSv1.3",
                Arrays.asList(engine.getEnabledCipherSuites()).contains("TLS_AES_128_GCM_SHA256"));
    }

    @Test
    public void secretsTest() {
        assertArrayEquals(
                h2ba(connIDStr),
                connID.getBytes());
        assertArrayEquals(
                h2ba("524e374c6da8cf8b496f4bcb696783507aafee6198b202b4bc823ebf7514a423"),
                secrets.initialSecret);
        assertArrayEquals(
                h2ba("fda3953aecc040e48b34e27ef87de3a6098ecf0e38b7e032c5c57bcbd5975b84"),
                secrets.clientInitialSecret);
        assertArrayEquals(
                h2ba("554366b81912ff90be41f17e8022213090ab17d8149179bcadf222f29ff2ddd5"),
                secrets.serverInitialSecret);

        assertArrayEquals(
                h2ba("af7fd7efebd21878ff66811248983694"),
                secrets.clientSecrets.key);
        assertArrayEquals(
                h2ba("8681359410a70bb9c92f0420"),
                secrets.clientSecrets.iv);
        assertArrayEquals(
                h2ba("a980b8b4fb7d9fbc13e814c23164253d"),
                secrets.clientSecrets.hp);

        assertArrayEquals(
                h2ba("5d51da9ee897a21b2659ccc7e5bfa577"),
                secrets.serverSecrets.key);
        assertArrayEquals(
                h2ba("5e5ae651fd1e8495af13508b"),
                secrets.serverSecrets.iv);
        assertArrayEquals(
                h2ba("a8ed82e6664f865aedf6106943f95fb8"),
                secrets.serverSecrets.hp);
    }

    void setQuicParam(SSLEngine engine, String name, long value) {
        SSLParameters params = (SSLParameters) engine.getSSLParameters();
        params.setQuicTransParam(name, value);
        engine.setSSLParameters(params);
    }

    @Test
    public void rawHandshake() throws Exception {
        SSLEngine client = context.createSSLEngine("dummy.example.com", 80);
        SSLEngine server = context.createSSLEngine();

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
            checkStatus(client.wrap(clientOut, cToS), client);
            checkStatus(server.wrap(serverOut, sToC), server);

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
