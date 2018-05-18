package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

public class ResponseMainModeThird extends ResponseDecryptBase {

    public ResponseMainModeThird(ByteBuffer buffer) {
        super(buffer);
    }

    @Override
    boolean isDataValid() {
        return (super.isDataValid()
                && isakmpHeader.exchangeType == Constants.EXCHANGE_TYPE_MAIN_MODE);
    }

    @Override
    void parseData(ByteBuffer buffer) {
        while (next > 0) {
            PayloadBase payload = parsePayload(next, buffer);
            if (payload != null) {
                payloadList.add(payload);
                next = payload.nextPayload;
                if (payload instanceof PayloadIdentification) {
                    generateHash((PayloadIdentification)payload);
                }

                if (payload instanceof PayloadHash) {
                    hashData = ((PayloadHash) payload).hashData;
                    hashCompare();
                }
            }else {
                break;
            }
        }

    }

    @Override
    void generateHash(byte[] data) {

    }

    @Override
    boolean prepareIV() {
        return true;
    }

    void generateHash(PayloadIdentification payload) {
        byte[] idPayload = new byte[payload.payloadLength - 4];
        System.arraycopy(Utils.toBytes(payload.type, 1), 0, idPayload, 0, 1);
        System.arraycopy(payload.doiData, 0, idPayload, 1, 3);
        System.arraycopy(payload.data, 0, idPayload, 4, payload.data.length);
        hashGenerated = KeyExchangeUtil.getInstance().generateResponder1stHashData(
                isakmpHeader.initiatorCookie,
                isakmpHeader.responderCookie,
                idPayload
        );

    }

    @Override
    public boolean isValid() {
        return (isakmpHeader != null && payloadList.size() >= 2 && hashMatched);
    }

}
