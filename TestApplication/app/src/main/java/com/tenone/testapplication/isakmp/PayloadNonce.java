package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

/**
 * Created by willwang on 2018-05-04.
 */

public class PayloadNonce extends PayloadBase {
    public byte[] nonceData;

    public PayloadNonce(ByteBuffer buffer) {
        super(buffer);
        if (isValid()) {
            nonceData = new byte[payloadLength - 4];
            buffer.get(nonceData, 0, payloadLength - 4);
        }
    }
}
