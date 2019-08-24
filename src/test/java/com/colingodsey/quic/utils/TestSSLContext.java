package com.colingodsey.quic.utils;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.function.BiConsumer;

import com.colingodsey.quic.crypto.TLS;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class TestSSLContext {
    public final static SSLContext sslContext;

    final static KeyManagerFactory kmf;
    final static TrustManagerFactory tmf;

    static {
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

            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), QUICRandom.getSecureRandom());
        } catch (Exception e) {
            throw new RuntimeException("failed to load test materials", e);
        }
    }

    public static ChannelInitializer<Channel> simpleHandler(BiConsumer<ChannelHandlerContext, Object> func) {
        return new ChannelInitializer<Channel>() {
            protected void initChannel(Channel ch) {
                ch.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                    public void channelRead(ChannelHandlerContext ctx, Object msg) {
                        func.accept(ctx, msg);
                    }
                });
            }
        };
    }
}
