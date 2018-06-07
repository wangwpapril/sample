package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

public class ResponseConfigModeFirst extends ResponseDecryptBase {

    public ResponseConfigModeFirst(ByteBuffer buffer) {
        super(buffer);
    }

    @Override
    boolean isDataValid() {
        return (super.isDataValid()
                && isakmpHeader.exchangeType == Constants.EXCHANGE_TYPE_CONFIG_MODE);
    }

    @Override
    void parseData(ByteBuffer buffer) {
        super.parseData(buffer);
        generateHash();
        hashCompare();
    }

    @Override
    public boolean isValid() {
        return super.isValid() && attributeSize == 2;
    }

    @Override
    boolean prepareIV() {
        PayloadHelper.getInstance().preparePhase2IV(Utils.toBytes(isakmpHeader.messageId));
        return true;
    }
}
