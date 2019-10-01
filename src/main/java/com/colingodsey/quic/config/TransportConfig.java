package com.colingodsey.quic.config;

import static com.colingodsey.quic.QUIC.*;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelOption;

import java.nio.ByteBuffer;
import java.text.MessageFormat;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import com.colingodsey.quic.QUIC;
import com.colingodsey.quic.crypto.TLS;
import com.colingodsey.quic.crypto.TLS.TransportParams;
import com.colingodsey.quic.packet.components.ConnectionID;
import com.colingodsey.quic.utils.VariableInt;

//TODO: package-protected access class ?
public class TransportConfig {
    final ChannelOption<?>[] OPTIONS = new ChannelOption<?>[] {
        ORIGINAL_CONNECTION_ID, IDLE_TIMEOUT, STATELESS_RESET_TOKEN,
        MAX_PACKET_SIZE, MAX_DATA, MAX_STREAM_DATA_BIDI_LOCAL,
        MAX_STREAM_DATA_BIDI_REMOTE, MAX_STREAM_DATA_UNI,
        ACK_DELAY_EXPONENT, MAX_ACK_DELAY, DISABLE_MIGRATION,
        ACTIVE_CONNECTION_ID_LIMIT
    };

    static public class Remote extends Core implements QUIC.Config.Transport.Immutable, TLS.TransportParams.ValueConsume {
        public void consumeTLS(ByteBuf data) {
            boolean disableMigration = false;
            while (data.isReadable()) {
                final TransportParams key = TransportParams.get(data.readUnsignedShort());
                switch (key) {
                    case original_connection_id: {
                        setOriginalConnectionID(ConnectionID.read(data));
                        break;
                    }
                    case stateless_reset_token: {
                        byte[] bytes = new byte[16];
                        data.readBytes(bytes);
                        setStatelessResetToken(bytes);
                        break;
                    }
                    case disable_migration:
                        disableMigration = true;
                        break;
                    //case preferred_address: //TODO: Preferred Address format
                    //    throw new UnsupportedOperationException();
                    default:
                        setOptionLong(key.option, VariableInt.read(data));
                }
            }
            setDisableMigration(disableMigration);
        }

        public void consumeTLS(ByteBuffer data) {
            if (data != null) {
                consumeTLS(Unpooled.wrappedBuffer(data));
            }
        }
        
        protected void dirty(ChannelOption<?> option) {
            // NOOP
        }
    }

    static public class Local extends Core implements QUIC.Config.Transport.Mutable, TLS.TransportParams.ValueProduce {
        ConcurrentHashMap<ChannelOption<?>, Object> dirtySet = new ConcurrentHashMap<>();

        public ByteBuffer produceDirtyTLS() {
            final ByteBuf buffer = Unpooled.buffer(64);

            produceDirty(option -> {
                if (option == DISABLE_MIGRATION && !isDisableMigration()) {
                    return;
                }

                buffer.writeShort(TransportParams.get(option).id);
                if (option == ORIGINAL_CONNECTION_ID) {
                    getOriginalConnectionID().write(buffer);
                } else if (option == STATELESS_RESET_TOKEN) {
                    buffer.writeBytes(getStatelessResetToken());
                } else if (option == DISABLE_MIGRATION) {
                    // no value here
                /*} else if (option == preferred_address) {

                }*/
                } else {
                    VariableInt.write(getOptionLong(option), buffer);
                }
            });

            if (buffer.isReadable()) {
                return buffer.nioBuffer();
            } else {
                return null;
            }
        }

        public void produceDirty(Consumer<ChannelOption<?>> consumer) {
            final Iterator<ChannelOption<?>> itr = dirtySet.keySet().iterator();
            while (itr.hasNext()) {
                final ChannelOption<?> option = itr.next();
                itr.remove();
                consumer.accept(option);
            }
        }

        protected void dirty(ChannelOption<?> option) {
            dirtySet.put(option, this);
        }
    }

    static public abstract class LocalProducer {

    }

    static abstract class Core {
        volatile ConnectionID originalConnectionID;
        volatile int idleTimeout = 0;
        volatile byte[] statelessResetToken; //TODO: Token class
        volatile int maxPacketSize = 1200;
        volatile long maxData = 0;
        volatile long maxStreamDataBiDiLocal = 0;
        volatile long maxStreamDataBiDiRemote = 0;
        volatile long maxStreamDataUni = 0;
        volatile long maxStreamsBiDi = 0;
        volatile long maxStreamsUni = 0;
        volatile int ackDelayExponent = 3;
        volatile int maxAckDelay = 25;
        volatile boolean disableMigration = false;
        //volatile //preferredAddress
        volatile int activeConnectionIdLimit = 0;

        protected abstract void dirty(ChannelOption<?> option);

        public ConnectionID getOriginalConnectionID() {
            return originalConnectionID;
        }

        public int getIdleTimeout() {
            return idleTimeout;
        }

        public byte[] getStatelessResetToken() {
            return statelessResetToken;
        }

        public int getMaxPacketSize() {
            return maxPacketSize;
        }

        public long getMaxData() {
            return maxData;
        }

        public long getMaxStreamDataBiDiLocal() {
            return maxStreamDataBiDiLocal;
        }

        public long getMaxStreamDataBiDiRemote() {
            return maxStreamDataBiDiRemote;
        }

        public long getMaxStreamDataUni() {
            return maxStreamDataUni;
        }

        public long getMaxStreamsBiDi() {
            return maxStreamsBiDi;
        }

        public long getMaxStreamsUni() {
            return maxStreamsUni;
        }

        public int getAckDelayExponent() {
            return ackDelayExponent;
        }

        public int getMaxAckDelay() {
            return maxAckDelay;
        }

        public boolean isDisableMigration() {
            return disableMigration;
        }

        public int getActiveConnectionIdLimit() {
            return activeConnectionIdLimit;
        }

        public void setOriginalConnectionID(ConnectionID originalConnectionID) {
            this.originalConnectionID = originalConnectionID;
            dirty(ORIGINAL_CONNECTION_ID);
        }

        public void setIdleTimeout(long idleTimeout) {
            this.idleTimeout = (int) idleTimeout;
            dirty(IDLE_TIMEOUT);
        }

        public void setStatelessResetToken(byte[] statelessResetToken) {
            this.statelessResetToken = statelessResetToken;
            dirty(STATELESS_RESET_TOKEN);
        }

        public void setMaxPacketSize(long maxPacketSize) {
            checkArgument(1200, 65527, maxPacketSize, "maxPacketSize");
            this.maxPacketSize = (int) maxPacketSize;
            dirty(MAX_PACKET_SIZE);
        }

        public void setMaxData(long maxData) {
            checkArgument(this.maxData, Long.MAX_VALUE, maxData, "maxData");
            this.maxData = maxData;
            dirty(MAX_DATA);
        }

        public void setMaxStreamDataBiDiLocal(long maxStreamDataBiDiLocal) {
            checkArgument(this.maxStreamDataBiDiLocal, Long.MAX_VALUE,
                    maxStreamDataBiDiLocal, "maxStreamDataBiDiLocal");
            this.maxStreamDataBiDiLocal = maxStreamDataBiDiLocal;
            dirty(MAX_STREAM_DATA_BIDI_LOCAL);
        }

        public void setMaxStreamDataBiDiRemote(long maxStreamDataBiDiRemote) {
            checkArgument(this.maxStreamDataBiDiRemote, Long.MAX_VALUE,
                    maxStreamDataBiDiRemote, "maxStreamDataBiDiLocal");
            this.maxStreamDataBiDiRemote = maxStreamDataBiDiRemote;
            dirty(MAX_STREAM_DATA_BIDI_REMOTE);
        }

        public void setMaxStreamDataUni(long maxStreamDataUni) {
            checkArgument(this.maxStreamDataUni, Long.MAX_VALUE,
                    maxStreamDataUni, "maxStreamDataUni");
            this.maxStreamDataUni = maxStreamDataUni;
            dirty(MAX_STREAM_DATA_UNI);
        }

        public void setMaxStreamsBiDi(long maxStreamsBiDi) {
            this.maxStreamsBiDi = maxStreamsBiDi;
            dirty(MAX_STREAMS_BIDI);
        }

        public void setMaxStreamsUni(long maxStreamsUni) {
            this.maxStreamsUni = maxStreamsUni;
            dirty(MAX_STREAMS_UNI);
        }

        public void setAckDelayExponent(long ackDelayExponent) {
            checkArgument(1, 20, ackDelayExponent, "ackDelayExponent");
            this.ackDelayExponent = (int) ackDelayExponent;
            dirty(ACK_DELAY_EXPONENT);
        }

        public void setMaxAckDelay(long maxAckDelay) {
            checkArgument(1, 2^14, maxAckDelay, "maxAckDelay");
            this.maxAckDelay = (int) maxAckDelay;
            dirty(MAX_ACK_DELAY);
        }

        public void setDisableMigration(boolean disableMigration) {
            this.disableMigration = disableMigration;
            dirty(DISABLE_MIGRATION);
        }

        public void setActiveConnectionIdLimit(long activeConnectionIdLimit) {
            this.activeConnectionIdLimit = (int) activeConnectionIdLimit;
            dirty(ACTIVE_CONNECTION_ID_LIMIT);
        }

        boolean setOptionLong(ChannelOption<?> option, long value) {
            if (option == IDLE_TIMEOUT) setIdleTimeout(value);
            else if (option == MAX_PACKET_SIZE) setMaxPacketSize(value);
            else if (option == MAX_DATA) setMaxData(value);
            else if (option == MAX_STREAM_DATA_BIDI_LOCAL) setMaxStreamDataBiDiLocal(value);
            else if (option == MAX_STREAM_DATA_BIDI_REMOTE) setMaxStreamDataBiDiRemote(value);
            else if (option == MAX_STREAM_DATA_UNI) setMaxStreamsUni(value);
            else if (option == MAX_STREAMS_BIDI) setMaxStreamsBiDi(value);
            else if (option == MAX_STREAMS_UNI) setMaxStreamsUni(value);
            else if (option == ACK_DELAY_EXPONENT) setAckDelayExponent(value);
            else if (option == MAX_ACK_DELAY) setMaxAckDelay(value);
            else if (option == ACTIVE_CONNECTION_ID_LIMIT) setActiveConnectionIdLimit(value);
            else {
                return false;
            }
            return true;
        }

        long getOptionLong(ChannelOption<?> option) {
            if (option == IDLE_TIMEOUT) return getIdleTimeout();
            else if (option == MAX_PACKET_SIZE) return getMaxPacketSize();
            else if (option == MAX_DATA) return getMaxData();
            else if (option == MAX_STREAM_DATA_BIDI_LOCAL) return getMaxStreamDataBiDiLocal();
            else if (option == MAX_STREAM_DATA_BIDI_REMOTE) return getMaxStreamDataBiDiRemote();
            else if (option == MAX_STREAM_DATA_UNI) return getMaxStreamsUni();
            else if (option == MAX_STREAMS_BIDI) return getMaxStreamsBiDi();
            else if (option == MAX_STREAMS_UNI) return getMaxStreamsUni();
            else if (option == ACK_DELAY_EXPONENT) return getAckDelayExponent();
            else if (option == MAX_ACK_DELAY) return getMaxAckDelay();
            else if (option == ACTIVE_CONNECTION_ID_LIMIT) return getActiveConnectionIdLimit();
            else {
                return -1;
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
}
