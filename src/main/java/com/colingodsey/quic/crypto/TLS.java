package com.colingodsey.quic.crypto;

import static com.colingodsey.quic.QUIC.ACK_DELAY_EXPONENT;
import static com.colingodsey.quic.QUIC.ACTIVE_CONNECTION_ID_LIMIT;
import static com.colingodsey.quic.QUIC.DISABLE_MIGRATION;
import static com.colingodsey.quic.QUIC.IDLE_TIMEOUT;
import static com.colingodsey.quic.QUIC.MAX_ACK_DELAY;
import static com.colingodsey.quic.QUIC.MAX_DATA;
import static com.colingodsey.quic.QUIC.MAX_PACKET_SIZE;
import static com.colingodsey.quic.QUIC.MAX_STREAMS_BIDI;
import static com.colingodsey.quic.QUIC.MAX_STREAMS_UNI;
import static com.colingodsey.quic.QUIC.MAX_STREAM_DATA_BIDI_LOCAL;
import static com.colingodsey.quic.QUIC.MAX_STREAM_DATA_BIDI_REMOTE;
import static com.colingodsey.quic.QUIC.MAX_STREAM_DATA_UNI;
import static com.colingodsey.quic.QUIC.ORIGINAL_CONNECTION_ID;
import static com.colingodsey.quic.QUIC.STATELESS_RESET_TOKEN;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelOption;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import com.colingodsey.quic.utils.QUICRandom;
import javax.net.ssl.SSLContext;

public class TLS {
    static final SSLContext context;

    static {
        try {
            Security.insertProviderAt(new org.openjsse.net.ssl.OpenJSSE(), 1);

            context = SSLContext.getInstance("TLS");
            context.init(null, null, QUICRandom.getSecureRandom());
            context.createSSLEngine();
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize TLS context: ", e);
        }
    }

    public static void init() {
        // NOOP
    }

    private TLS() {
        // NOOP
    }

    public enum TransportParams {
        original_connection_id(0, ORIGINAL_CONNECTION_ID),
        idle_timeout(1, IDLE_TIMEOUT),
        stateless_reset_token(2, STATELESS_RESET_TOKEN),
        max_packet_size(3, MAX_PACKET_SIZE),
        initial_max_data(4, MAX_DATA),
        initial_max_stream_data_bidi_local(5, MAX_STREAM_DATA_BIDI_LOCAL),
        initial_max_stream_data_bidi_remote(6, MAX_STREAM_DATA_BIDI_REMOTE),
        initial_max_stream_data_uni(7, MAX_STREAM_DATA_UNI),
        initial_max_streams_bidi(8, MAX_STREAMS_BIDI),
        initial_max_streams_uni(9, MAX_STREAMS_UNI),
        ack_delay_exponent(10, ACK_DELAY_EXPONENT),
        max_ack_delay(11, MAX_ACK_DELAY),
        disable_migration(12, DISABLE_MIGRATION),
        //preferred_address(13),
        active_connection_id_limit(14, ACTIVE_CONNECTION_ID_LIMIT);

        static final TransportParams[] idMap = new TransportParams[16];
        static final Map<ChannelOption<?>, TransportParams> optionMap = new HashMap<>();

        static {
            for (TransportParams value : values()) {
                idMap[value.id] = value;
                optionMap.put(value.option, value);
            }
        }

        static public TransportParams get(ChannelOption<?> option) {
            return optionMap.get(option);
        }

        static public TransportParams get(int id) {
            TransportParams out = idMap[id];
            if (out == null) {
                throw new IllegalArgumentException("Unknown QUIC Transport Param: " + id);
            }
            return out;
        }

        public final int id;
        public final ChannelOption<?> option;

        TransportParams(int id, ChannelOption<?> option) {
            this.id = id;
            this.option = option;
        }

        public interface ValueConsume {
            void consumeTLS(ByteBuffer data);
        }

        public interface ValueProduce {
            ByteBuffer produceDirtyTLS();
        }
    }
}
