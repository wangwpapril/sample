package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by willwang on 2018-05-03.
 */

public class PayloadBase {
    private static final int DEFAULT_SIZE = 1024;

    public byte nextPayload;
    public byte reserved;
    public int payloadLength;
    private int remaining;
    private List<byte[]> dataList;


    PayloadBase(ByteBuffer buffer) {
        nextPayload = buffer.get();
        reserved = buffer.get();
        payloadLength = buffer.getShort();
        remaining = buffer.remaining();
    }

    PayloadBase(ByteBuffer buffer, int length) {

    }

    PayloadBase(Builder builder) {
        this.dataList = builder.dataList;
    }

    public byte[] toData() {
        ByteBuffer byteBuffer = ByteBuffer.allocate(DEFAULT_SIZE);
        if (dataList != null && !dataList.isEmpty()) {
            for (byte[] data : dataList)
                byteBuffer.put(data);
        }

        int length = byteBuffer.position();
        byteBuffer.position(0);

        byte[] ret = new byte[length];
        byteBuffer.get(ret, 0, length);
        System.arraycopy(Utils.toBytes(length, 2), 0, ret, 2, 2);

        return ret;
    }

    protected boolean isValid() {
        return (payloadLength - 4 > 0 && payloadLength - 4 < remaining) ;
    }

    public static class Builder {
        protected List<byte[]> dataList = new ArrayList<>();

        public Builder nextPayload(int next) {
            this.dataList.add(0, Utils.toBytes(next, 1));
            this.dataList.add(1, Utils.toBytes(0, 1));
            this.dataList.add(2, Utils.toBytes(0, 2));
            return this;
        }

        public PayloadBase Build() {
            return new PayloadBase(this);
        }

    }
}
