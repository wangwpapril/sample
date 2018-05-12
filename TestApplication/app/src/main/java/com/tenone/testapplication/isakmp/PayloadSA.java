package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

/**
 * Created by willwang on 2018-05-03.
 */

public class PayloadSA extends PayloadBase{
    public int doi;
    public int situation;
    public PayloadProposal payloadProposal;

    public PayloadSA(ByteBuffer buffer) {
        super(buffer);
        doi = buffer.getInt();
        situation = buffer.getInt();

        payloadProposal = new PayloadProposal(buffer);
    }
}
