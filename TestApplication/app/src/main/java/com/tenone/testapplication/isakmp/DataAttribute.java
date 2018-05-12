package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

/**
 * Created by willwang on 2018-05-03.
 */

public class DataAttribute {
    public static final int FLAG = 0x8000;

    public short type;
    public int attLength;
    public byte[] value;

    public int totalLength;

    public DataAttribute(ByteBuffer buffer) {
        type = buffer.getShort();

        if (isValue()) {
            attLength = 2;
            totalLength = 4;
        }else {
            attLength = buffer.getInt();
            totalLength = 4 + attLength;
        }
        value = new byte[attLength];
        buffer.get(value, 0, attLength);

    }

    private boolean isValue() {
        return (type & FLAG) == FLAG;
    }
}
