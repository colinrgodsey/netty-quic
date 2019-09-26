package com.colingodsey.quic.packet;

public class VersionNegotiation {
    /*public final LongHeader meta;
    public final int[] versions;

    public VersionNegotiation(ByteBuf in) {
        final ArrayList<Integer> versionsArr = new ArrayList<>();
        meta = new LongHeader(in);
        while (in.isReadable()) {
            versionsArr.add(in.readInt());
        }
        versions = new int[versionsArr.size()];
        for (int i = 0 ; i < versions.length ; i++) {
            versions[i] = versionsArr.get(i);
        }
    }

    public VersionNegotiation(ConnectionID sourceID, ConnectionID destID, int[] versions) {
        this.meta = new LongHeader(Type.random(), QUICRandom.nextNibble(), 0, sourceID, destID);
        this.versions = versions;
    }

    public void writeHeader(ByteBuf out) {
        meta.writeHeader(out);
        for (int version : versions) {
            out.writeInt(version);
        }
    }

    public Header getHeader() {
        return meta;
    }*/
}
