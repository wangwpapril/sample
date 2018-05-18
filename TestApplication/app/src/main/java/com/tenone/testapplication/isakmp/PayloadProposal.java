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
    public byte[] spiData;
    public List<PayloadTransform> transformList = new ArrayList<>();

    public PayloadProposal(ByteBuffer buffer) {
        super(buffer);

        if (isValid()) {
            number = buffer.get();
            protocolId = buffer.get();
            spiSize = buffer.get();
            transformNumber = buffer.get();

            if (spiSize > 0) {
                spiData = new byte[spiSize];
                buffer.get(spiData, 0, spiSize);
            }

            if (transformNumber > 0) {
                for (int i = 0; i < transformNumber; i++) {
                    PayloadTransform payloadTransform = new PayloadTransform(buffer);
                    if (payloadTransform != null)
                        transformList.add(payloadTransform);
                }
            }
        }
    }
}
