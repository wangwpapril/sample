package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

public class ResponseConfigModeSecond extends ResponseDecryptBase {

    public ResponseConfigModeSecond(ByteBuffer buffer) {
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
    boolean prepareIV() {
        KeyExchangeUtil.getInstance().preparePhase2IV(Utils.toBytes(isakmpHeader.messageId, 4));
        return true;
    }

    @Override
    public boolean isValid() {
        return super.isValid() && attributeSize == 1;
    }
}
