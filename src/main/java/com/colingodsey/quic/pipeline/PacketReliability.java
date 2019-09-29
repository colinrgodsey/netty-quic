package com.colingodsey.quic.pipeline;

import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelPromise;

import java.util.ArrayDeque;
import java.util.Queue;

import com.colingodsey.quic.packet.Packet;
import com.colingodsey.quic.packet.frame.Frame;
import com.colingodsey.quic.utils.Tuple;

import it.unimi.dsi.fastutil.longs.Long2ObjectMap;
import it.unimi.dsi.fastutil.longs.Long2ObjectOpenHashMap;

public class PacketReliability extends ChannelDuplexHandler {
    final Packet.Type type;
    Queue<Tuple<Frame, ChannelPromise>> frameQueue = new ArrayDeque<>();
    Long2ObjectMap<Packet> pendingPackets = new Long2ObjectOpenHashMap<>();
    long packetNumber = 0;

    public PacketReliability(Packet.Type type) {
        this.type = type;
    }
}
