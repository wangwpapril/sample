package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

public class ResponseInformational extends ResponseDecryptBase {

    public ResponseInformational(ByteBuffer buffer) {
        super(buffer);
    }

    @Override
    boolean isDataValid() {
        return (super.isDataValid()
                && isakmpHeader.exchangeType == Constants.EXCHANGE_TYP_INFORMATIONAL);
    }

    @Override
    void parseData(ByteBuffer buffer) {
        super.parseData(buffer);
        generateHash();
        hashCompare();
    }


    @Override
    boolean prepareIV() {
        PayloadHelper.getInstance().preparePhase2IV(Utils.toBytes(isakmpHeader.messageId));
        return true;
    }

    public boolean isDeleteSA() {
        return payloadList != null && hasDeletePayload;
    }
}
