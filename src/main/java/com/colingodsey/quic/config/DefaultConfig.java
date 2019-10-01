package com.colingodsey.quic.config;

import io.netty.channel.Channel;
import io.netty.channel.DefaultChannelConfig;

import com.colingodsey.quic.QUIC;
import com.colingodsey.quic.crypto.context.CryptoContext;

public class DefaultConfig extends DefaultChannelConfig implements QUIC.Config {
    private final TransportConfig.Remote remoteTransport = new TransportConfig.Remote();
    private final TransportConfig.Local localTransport = new TransportConfig.Local();
    private volatile CryptoContext initialContext = null;
    private volatile CryptoContext handshakeContext = null;
    private volatile CryptoContext masterContext = null;
    private volatile int frameSplitSize = 512;

    public DefaultConfig(Channel channel) {
        super(channel);
    }

    public CryptoContext getInitialContext() {
        return initialContext;
    }
    public void setInitialContext(CryptoContext initialContext) {
        this.initialContext = initialContext;
    }

    public CryptoContext getHandshakeContext() {
        return handshakeContext;
    }
    public void setHandshakeContext(CryptoContext handshakeContext) {
        this.handshakeContext = handshakeContext;
    }

    public CryptoContext getMasterContext() {
        return masterContext;
    }
    public void setMasterContext(CryptoContext masterContext) {
        this.masterContext = masterContext;
    }

    public int getFrameSplitSize() {
        return frameSplitSize;
    }

    public void setFrameSplitSize(int size) {
        frameSplitSize = size;
    }

    public Transport.Immutable getRemoteTransport() {
        return remoteTransport;
    }

    public Transport.Mutable getLocalTransport() {
        return localTransport;
    }
}
