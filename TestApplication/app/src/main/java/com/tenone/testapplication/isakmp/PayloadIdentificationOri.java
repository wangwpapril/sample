package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

/**
 * Created by willwang on 2018-05-07.
 */

public class PayloadIdentificationOri extends PayloadBase {
    private byte[] rawData;

    public PayloadIdentificationOri(ByteBuffer buffer) {
        super(buffer);
    }

    public PayloadIdentificationOri(ByteBuffer buffer, int length) {
        super(buffer, length);
        rawData = new byte[length];
        buffer.get(rawData, 0, length);
    }
}
