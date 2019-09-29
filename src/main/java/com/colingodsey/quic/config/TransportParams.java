package com.colingodsey.quic.config;

import static com.colingodsey.quic.QUIC.*;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelOption;

import java.nio.ByteBuffer;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.function.Consumer;

import com.colingodsey.quic.packet.components.ConnectionID;
import com.colingodsey.quic.utils.VariableInt;

public class TransportParams {
    //TODO: store map of values here, attach to config. 2 copies, one that can be produced and one is received.
    //maybe this should attach to some kind of directional config? incoming and outgoing?
    //one copy will be immutable obviously, other can be derived directly from config
    //QUIC.Config.Transport - getters only?

    enum Type {
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

        static final Type[] idMap = new Type[16];
        static final Map<ChannelOption<?>, Type> optionMap = new HashMap<>();

        static {
            for (Type value : values()) {
                idMap[value.id] = value;
                optionMap.put(value.option, value);
            }
        }

        static Type get(int id) {
            Type out = idMap[id];
            if (out == null) {
                throw new IllegalArgumentException("Unknown QUIC Transport Param: " + id);
            }
            return out;
        }

        final int id;
        final ChannelOption<?> option;

        Type(int id, ChannelOption<?> option) {
            this.id = id;
            this.option = option;
        }
    }

    static public void consumeTLS(ByteBuf data, TransportConfig.Remote config) {
        boolean disableMigration = false;
        while (data.isReadable()) {
            final Type key = Type.get(data.readUnsignedShort());
            switch (key) {
                case original_connection_id: {
                    config.setOriginalConnectionID(ConnectionID.read(data));
                    break;
                }
                case stateless_reset_token: {
                    byte[] bytes = new byte[16];
                    data.readBytes(bytes);
                    config.setStatelessResetToken(bytes);
                    break;
                }
                case disable_migration:
                    disableMigration = true;
                    break;
                //case preferred_address: //TODO: Preferred Address format
                //    throw new UnsupportedOperationException();
                default:
                    config.setOptionLong(key.option, VariableInt.read(data));
            }
        }
        config.setDisableMigration(disableMigration);
    }

    public void consumeTLS(ByteBuffer data, TransportConfig.Remote config) {
        consumeTLS(Unpooled.wrappedBuffer(data), config);
    }

    public ByteBuf produceDirtyTLS(TransportConfig.Local config) {
        final ByteBuf buffer = Unpooled.buffer(64);
        final Iterator<ChannelOption<?>> itr = config.dirtySet.iterator();

        produceDirty(config, option -> {
            if (option == DISABLE_MIGRATION && !config.isDisableMigration()) {
                return;
            }

            buffer.writeShort(Type.optionMap.get(config).id);
            if (option == ORIGINAL_CONNECTION_ID) {
                config.getOriginalConnectionID().write(buffer);
            } else if (option == STATELESS_RESET_TOKEN) {
                buffer.writeBytes(config.getStatelessResetToken());
            } else if (option == DISABLE_MIGRATION) {
                // no value here
            /*} else if (option == preferred_address) {

            }*/
            } else {
                VariableInt.write(config.getOptionLong(option), buffer);
            }
        });

        return buffer;
    }

    public void produceDirty(TransportConfig.Local config, Consumer<ChannelOption<?>> consumer) {
        final Iterator<ChannelOption<?>> itr = config.dirtySet.iterator();
        while (itr.hasNext()) {
            final ChannelOption<?> option = itr.next();
            itr.remove();
            consumer.accept(option);
        }
    }

    static void checkArgument(long min, long max, long value, String fieldName) {
        if (value < min || value > max) {
            final MessageFormat msg = new MessageFormat(
                    "Value {0} for {1} is outside of the allowed bounds of {2} to {3}.");
            //TODO: TRANSPORT_PARAMETER_ERROR
            throw new IllegalArgumentException(
                    msg.format(new Object[] {value, fieldName, min, max}));
        }
    }
}
