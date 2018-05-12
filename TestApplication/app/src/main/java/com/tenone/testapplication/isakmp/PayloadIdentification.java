package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

/**
 * Created by willwang on 2018-05-07.
 */

public class PayloadIdentification extends PayloadBase {
    public byte type;
    public byte[] doiData = new byte[3];
    public byte[] data;

    public PayloadIdentification(ByteBuffer buffer) {
        super(buffer);

        type = buffer.get();
        buffer.get(doiData, 0, 3);

        data = new byte[payloadLength - 8];
        buffer.get(data, 0, payloadLength - 8);

    }
}
