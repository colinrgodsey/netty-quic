package com.colingodsey.quic;

import io.netty.channel.ChannelConfig;
import io.netty.channel.ChannelOption;

public class QUIC {
    /*public static final ChannelOption<DerivedSecrets> INITIAL_SECRETS = ChannelOption.valueOf("QUIC_INITIAL_SECRETS");
    public static final ChannelOption<DerivedSecrets> HANDSHAKE_SECRETS = ChannelOption.valueOf("QUIC_HANDSHAKE_SECRETS");
    public static final ChannelOption<DerivedSecrets> TLS_SECRETS = ChannelOption.valueOf("QUIC_TLS_SECRETS");*/

    public interface Config extends ChannelConfig {
        /*DerivedSecrets getInitialSecrets();
        void setInitialSecrets(DerivedSecrets secrets);

        DerivedSecrets getHandshakeSecrets();
        void setHandshakeSecrets(DerivedSecrets secrets);

        DerivedSecrets getTLSSecrets();
        void setTLSSecrets(DerivedSecrets secrets);*/
    }
}
