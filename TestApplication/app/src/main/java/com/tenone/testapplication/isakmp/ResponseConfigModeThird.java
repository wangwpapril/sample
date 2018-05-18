package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

public class ResponseConfigModeThird extends ResponseDecryptBase {

    public ResponseConfigModeThird(ByteBuffer buffer) {
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
        hashCompare();
    }

    @Override
    void generateHash(byte[] payload) {
        hashGenerated = KeyExchangeUtil.getInstance().generateHashDataForAttributePayload(
                Utils.toBytes(isakmpHeader.messageId, 4),
                payload
        );

    }

    @Override
    boolean prepareIV() {
        return true;
    }

    @Override
    public boolean isValid() {
        return super.isValid() && attributeType == 2;
    }
}
