package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by willwang on 2018-05-03.
 */

public class PayloadProposal extends PayloadBase{
    public byte number;
    public byte protocolId;
    public byte spiSize;
    public byte transformNumber;
    public List<PayloadTransform> transformList = new ArrayList<>();

    public PayloadProposal(ByteBuffer buffer) {
        super(buffer);

        number = buffer.get();
        protocolId = buffer.get();
        spiSize = buffer.get();
        transformNumber = buffer.get();

        if (transformNumber > 0) {
            for (int i = 0; i < transformNumber; i++) {
                PayloadTransform payloadTransform = new PayloadTransform(buffer);
                if (payloadTransform != null)
                    transformList.add(payloadTransform);
            }
        }
    }
}
