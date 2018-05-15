package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class ResponseMainModeThird extends ResponseBase {
    private byte[] encryptedData;
    private byte[] hashGenerated;
    private boolean hashMatched = true;

    public ResponseMainModeThird(ByteBuffer buffer) {
        super(buffer);
    }

    @Override
    boolean isDataValid() {
        return (isakmpHeader != null
                && isakmpHeader.isEncrypted()
                && isakmpHeader.exchangeType == Constants.EXCHANGE_TYPE_MAIN_MODE);
    }

    @Override
    void parseData(ByteBuffer buffer) {

        encryptedData = new byte[isakmpHeader.payloadLength - 28];
        buffer.get(encryptedData, 0, isakmpHeader.payloadLength - 28);
        byte[] decryptedData = KeyExchangeUtil.getInstance().decryptData(encryptedData);
        if (decryptedData != null) {
            buffer.clear();
            buffer.put(decryptedData);
            buffer.position(0);
        }else {
            buffer.clear();
            next = 0;
        }

        while (next > 0) {
            PayloadBase payload = parsePayload(next, buffer);
            if (payload != null) {
                payloadList.add(payload);
                next = payload.nextPayload;
                if (payload instanceof PayloadIdentification) {
                    generateHash((PayloadIdentification)payload);
                }

                if (payload instanceof PayloadHash) {
                    hashCompare((PayloadHash) payload);
                }
            }else {
                break;
            }
        }

    }

    private void generateHash(PayloadIdentification payload) {
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

    private void hashCompare(PayloadHash payload) {
        if (hashGenerated != null && payload.hashData != null
                && hashGenerated.length == payload.hashData.length) {
            hashMatched = Arrays.equals(hashGenerated, payload.hashData);
        }
    }

    @Override
    public boolean isValid() {
        return (isakmpHeader != null && payloadList.size() >= 2 && hashMatched);
    }

    public byte[] getNextIv() {
        byte[] Iv = new byte[16];
        System.arraycopy(encryptedData, encryptedData.length - 16, Iv, 0, 16);
        return Iv;
    }

}
