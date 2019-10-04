package com.colingodsey.quic;

import io.netty.channel.Channel;
import io.netty.channel.ChannelConfig;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOption;

import java.util.function.Consumer;

import com.colingodsey.quic.crypto.context.CryptoContext;
import com.colingodsey.quic.packet.component.ConnectionID;

public class QUIC {
    /*public static final ChannelOption<CryptoContext> INITIAL_SECRETS = ChannelOption.valueOf("QUIC_INITIAL_SECRETS");
    public static final ChannelOption<CryptoContext> HANDSHAKE_SECRETS = ChannelOption.valueOf("QUIC_HANDSHAKE_SECRETS");
    public static final ChannelOption<CryptoContext> MASTER_SECRETS = ChannelOption.valueOf("QUIC_MASTER_SECRETS");*/

    public static final ChannelOption<ConnectionID> ORIGINAL_CONNECTION_ID = ChannelOption.valueOf("QUIC_ORIGINAL_CONNECTION_ID");
    public static final ChannelOption<Long> IDLE_TIMEOUT = ChannelOption.valueOf("QUIC_IDLE_TIMEOUT");
    public static final ChannelOption<byte[]> STATELESS_RESET_TOKEN = ChannelOption.valueOf("QUIC_STATELESS_RESET_TOKEN");
    public static final ChannelOption<Long> MAX_PACKET_SIZE = ChannelOption.valueOf("QUIC_MAX_PACKET_SIZE");
    public static final ChannelOption<Long> MAX_DATA = ChannelOption.valueOf("QUIC_MAX_DATA");
    public static final ChannelOption<Long> MAX_STREAM_DATA_BIDI_LOCAL = ChannelOption.valueOf("QUIC_MAX_STREAM_DATA_BIDI_LOCAL");
    public static final ChannelOption<Long> MAX_STREAM_DATA_BIDI_REMOTE = ChannelOption.valueOf("QUIC_MAX_STREAM_DATA_BIDI_REMOTE");
    public static final ChannelOption<Long> MAX_STREAM_DATA_UNI = ChannelOption.valueOf("QUIC_MAX_STREAM_DATA_UNI");
    public static final ChannelOption<Long> MAX_STREAMS_BIDI = ChannelOption.valueOf("QUIC_MAX_STREAMS_BIDI");
    public static final ChannelOption<Long> MAX_STREAMS_UNI = ChannelOption.valueOf("QUIC_MAX_STREAMS_UNI");
    public static final ChannelOption<Long> ACK_DELAY_EXPONENT = ChannelOption.valueOf("QUIC_ACK_DELAY_EXPONENT");
    public static final ChannelOption<Long> MAX_ACK_DELAY = ChannelOption.valueOf("QUIC_MAX_ACK_DELAY");
    public static final ChannelOption<Boolean> DISABLE_MIGRATION = ChannelOption.valueOf("QUIC_DISABLE_MIGRATION");
    public static final ChannelOption<Object> PREFERRED_ADDRESS = ChannelOption.valueOf("QUIC_PREFERRED_ADDRESS");
    public static final ChannelOption<Long> ACTIVE_CONNECTION_ID_LIMIT = ChannelOption.valueOf("QUIC_ACTIVE_CONNECTION_ID_LIMIT");

    public interface Config extends ChannelConfig {
        CryptoContext getInitialContext();
        void setInitialContext(CryptoContext Context);

        CryptoContext getHandshakeContext();
        void setHandshakeContext(CryptoContext Context);

        CryptoContext getMasterContext();
        void setMasterContext(CryptoContext Context);

        int getFrameSplitSize();
        void setFrameSplitSize(int size);

        Transport.Immutable getRemoteTransport();
        Transport.Mutable getLocalTransport();

        //TODO: preferred_address
        interface Transport {
            ConnectionID getOriginalConnectionID();
            int getIdleTimeout();
            byte[] getStatelessResetToken();
            int getMaxPacketSize();
            long getMaxData();
            long getMaxStreamDataBiDiLocal();
            long getMaxStreamDataBiDiRemote();
            long getMaxStreamDataUni();
            long getMaxStreamsBiDi();
            long getMaxStreamsUni();
            int getAckDelayExponent();
            int getMaxAckDelay();
            boolean isDisableMigration();
            //todo: pref addr
            int getActiveConnectionIdLimit();

            interface Immutable extends Transport {}

            interface Mutable extends Transport {
                void setOriginalConnectionID(ConnectionID originalConnectionID);
                void setIdleTimeout(long idleTimeout);
                void setStatelessResetToken(byte[] statelessResetToken);
                void setMaxPacketSize(long maxPacketSize);
                void setMaxData(long maxData);
                void setMaxStreamDataBiDiLocal(long maxStreamDataBiDiLocal);
                void setMaxStreamDataBiDiRemote(long maxStreamDataBiDiRemote);
                void setMaxStreamDataUni(long maxStreamDataUni);
                void setMaxStreamsBiDi(long maxStreamsBiDi);
                void setMaxStreamsUni(long maxStreamsUni);
                void setAckDelayExponent(long ackDelayExponent);
                void setMaxAckDelay(long maxAckDelay);
                void setDisableMigration(boolean disableMigration);
                void setActiveConnectionIdLimit(long activeConnectionIdLimit);
            }

            interface Accessor {
                long getOptionLong(ChannelOption<Long> option);
                void setOptionLong(ChannelOption<Long> option, long value);
                <T> T getOption(ChannelOption<T> option);
                <T> void setOption(ChannelOption<T> option, T value);
                void produceDirty(Consumer<ChannelOption<?>> consumer);
            }
        }
    }

    public static Config config(ChannelHandlerContext ctx) {
        return config(ctx.channel());
    }

    public static Config config(Channel channel) {
        return (Config) channel.config();
    }
}
