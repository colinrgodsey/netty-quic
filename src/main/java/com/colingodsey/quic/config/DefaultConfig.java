package com.colingodsey.quic.config;

import io.netty.channel.Channel;
import io.netty.channel.DefaultChannelConfig;

import com.colingodsey.quic.QUIC;
import com.colingodsey.quic.crypto.context.CryptoContext;

public class DefaultConfig extends DefaultChannelConfig implements QUIC.Config {
    private volatile CryptoContext initialContext = null;
    private volatile CryptoContext handshakeContext = null;
    private volatile CryptoContext masterContext = null;

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
}
