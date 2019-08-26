package com.colingodsey.quic;

import io.netty.channel.Channel;
import io.netty.channel.ChannelConfig;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOption;

import com.colingodsey.quic.crypto.context.CryptoContext;

public class QUIC {
    /*public static final ChannelOption<CryptoContext> INITIAL_SECRETS = ChannelOption.valueOf("QUIC_INITIAL_SECRETS");
    public static final ChannelOption<CryptoContext> HANDSHAKE_SECRETS = ChannelOption.valueOf("QUIC_HANDSHAKE_SECRETS");
    public static final ChannelOption<CryptoContext> MASTER_SECRETS = ChannelOption.valueOf("QUIC_MASTER_SECRETS");*/

    public interface Config extends ChannelConfig {
        CryptoContext getInitialContext();
        void setInitialContext(CryptoContext Context);

        CryptoContext getHandshakeContext();
        void setHandshakeContext(CryptoContext Context);

        CryptoContext getMasterContext();
        void setMasterContext(CryptoContext Context);

        int getFrameSplitSize();
        void setFrameSplitSize(int size);
    }

    public static Config config(ChannelHandlerContext ctx) {
        return config(ctx.channel());
    }

    public static Config config(Channel channel) {
        return (Config) channel.config();
    }
}
