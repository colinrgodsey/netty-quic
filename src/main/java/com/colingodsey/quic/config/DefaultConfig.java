package com.colingodsey.quic.config;

import io.netty.channel.Channel;
import io.netty.channel.DefaultChannelConfig;

import com.colingodsey.quic.QUIC;

public class DefaultConfig extends DefaultChannelConfig implements QUIC.Config {
    public DefaultConfig(Channel channel) {
        super(channel);
    }
}
