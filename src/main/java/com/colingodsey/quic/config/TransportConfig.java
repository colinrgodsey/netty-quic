package com.colingodsey.quic.config;

import static com.colingodsey.quic.QUIC.*;

import io.netty.channel.ChannelOption;

import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.ObjLongConsumer;
import java.util.function.ToLongFunction;

import com.colingodsey.quic.QUIC;
import com.colingodsey.quic.packet.component.ConnectionID;

public class TransportConfig {
    static final Map<ChannelOption<?>, Accessor<?>> accessors = new HashMap<>();

    static {
        addAccessorO(ORIGINAL_CONNECTION_ID, Core::getOriginalConnectionID, Core::setOriginalConnectionID);
        addAccessor(IDLE_TIMEOUT, Core::getIdleTimeout, Core::setIdleTimeout);
        addAccessorO(STATELESS_RESET_TOKEN, Core::getStatelessResetToken, Core::setStatelessResetToken);
        addAccessor(MAX_PACKET_SIZE, Core::getMaxPacketSize, Core::setMaxPacketSize);
        addAccessor(MAX_DATA, Core::getMaxData, Core::setMaxData);
        addAccessor(MAX_STREAM_DATA_BIDI_LOCAL, Core::getMaxStreamDataBiDiLocal, Core::setMaxStreamDataBiDiLocal);
        addAccessor(MAX_STREAM_DATA_BIDI_REMOTE, Core::getMaxStreamDataBiDiRemote, Core::setMaxStreamDataBiDiRemote);
        addAccessor(MAX_STREAM_DATA_UNI, Core::getMaxStreamDataUni, Core::setMaxStreamDataUni);
        addAccessor(ACK_DELAY_EXPONENT, Core::getAckDelayExponent, Core::setAckDelayExponent);
        addAccessor(MAX_ACK_DELAY, Core::getMaxAckDelay, Core::setMaxAckDelay);
        addAccessorO(DISABLE_MIGRATION, Core::isDisableMigration, Core::setDisableMigration);
        //addAccessor(PREFERRED_ADDRESS);
        addAccessor(ACTIVE_CONNECTION_ID_LIMIT, Core::getActiveConnectionIdLimit, Core::setActiveConnectionIdLimit);
    }

    static void addAccessor(ChannelOption<Long> option0,
            ToLongFunction<Core> getter0,
            ObjLongConsumer<Core> setter0) {
        accessors.put(option0, new Accessor<Long>() {
            final ToLongFunction<Core> getter = getter0;
            final ObjLongConsumer<Core> setter = setter0;

            public Long get(Core core) {
                return getter.applyAsLong(core);
            }

            public long getLong(Core core) {
                return getter.applyAsLong(core);
            }

            public void set(Core core, Long value) {
                setter.accept(core, value);
            }

            public void setLong(Core core, long value) {
                setter.accept(core, value);
            }
        });
    }

    static <T> void addAccessorO(ChannelOption<T> option0,
            Function<Core, T> getter0,
            BiConsumer<Core, T> setter0) {
        accessors.put(option0, new Accessor<T>() {
            final Function<Core, T>getter = getter0;
            final BiConsumer<Core, T> setter = setter0;

            public T get(Core core) {
                return getter.apply(core);
            }

            public long getLong(Core core) {
                return (Long) getter.apply(core);
            }

            public void set(Core core, T value) {
                setter.accept(core, value);
            }

            @SuppressWarnings("unchecked")
            public void setLong(Core core, long value) {
                setter.accept(core, (T) (Long) value);
            }
        });
    }

    static class Remote extends Core implements QUIC.Config.Transport.Immutable,
            QUIC.Config.Transport.Accessor {
        public long getOptionLong(ChannelOption<Long> option) {
            return accOf(option).getLong(this);
        }

        public void setOptionLong(ChannelOption<Long> option, long value) {
            accOf(option).setLong(this, value);
        }

        public <T> T getOption(ChannelOption<T> option) {
            return accOf(option).get(this);
        }

        public <T> void setOption(ChannelOption<T> option, T value) {
            accOf(option).set(this, value);
        }

        public void produceDirty(Consumer<ChannelOption<?>> consumer) {
            // NOOP
        }

        protected void dirty(ChannelOption<?> option) {
            // NOOP
        }
    }

    @SuppressWarnings("unchecked")
    static <T> Accessor<T> accOf(ChannelOption<T> option) {
        return (Accessor<T>) accessors.get(option);
    }

    static class Local extends Core implements QUIC.Config.Transport.Mutable,
            QUIC.Config.Transport.Accessor {
        ConcurrentHashMap<ChannelOption<?>, Object> dirtySet = new ConcurrentHashMap<>();

        public long getOptionLong(ChannelOption<Long> option) {
            return accOf(option).getLong(this);
        }

        public void setOptionLong(ChannelOption<Long> option, long value) {
            accOf(option).setLong(this, value);
        }

        public <T> T getOption(ChannelOption<T> option) {
            return accOf(option).get(this);
        }

        public <T> void setOption(ChannelOption<T> option, T value) {
            accOf(option).set(this, value);
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

        //TODO: some of these can only be set once
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

    interface Accessor<T> {
        T get(Core core);
        long getLong(Core core);
        void set(Core core, T value);
        void setLong(Core core, long value);
    }
}
