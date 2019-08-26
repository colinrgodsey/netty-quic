package io.netty.channel.embedded;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;

import java.util.function.Consumer;

import com.colingodsey.quic.QUIC;
import com.colingodsey.quic.config.DefaultConfig;

public class QUICTestChannel extends EmbeddedChannel {
    static final Channel DUMMY_CHANNEL = new EmbeddedChannel();

    public QUICTestChannel(final ChannelHandler... handlers) {
        super(EmbeddedChannelId.INSTANCE, false, new DefaultConfig(DUMMY_CHANNEL), handlers);
    }

    public QUICTestChannel(Consumer<QUIC.Config> cfg, final ChannelHandler... handlers) {
        super(EmbeddedChannelId.INSTANCE, false, makeConfig(cfg), handlers);
    }

    static QUIC.Config makeConfig(Consumer<QUIC.Config> cfg) {
        QUIC.Config out = new DefaultConfig(DUMMY_CHANNEL);
        cfg.accept(out);
        return out;
    }
}
