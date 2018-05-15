package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

/**
 * Created by willwang on 2018-05-04.
 */

public class PayloadNatD extends PayloadBase {
    public byte[] natData;

    public PayloadNatD(ByteBuffer buffer) {
        super(buffer);
        if (isValid()) {
            natData = new byte[payloadLength - 4];
            buffer.get(natData, 0, payloadLength - 4);
        }
    }
}
