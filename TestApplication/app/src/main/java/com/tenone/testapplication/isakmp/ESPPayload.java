package com.tenone.testapplication.isakmp;

import android.util.Log;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class ESPPayload {
    public byte[] spi;
    public int sequence;
    public byte[] Iv;
    public byte[] encryptedData;
    public byte[] decryptedData;
    public byte[] ICV;
    public byte[] padLength;
    public byte[] nextHeader;
    public byte[] payload;

    private static final String TAG = "ESPPayload";


    public ESPPayload(ByteBuffer buffer) {
        spi = new byte[4];
        buffer.get(spi, 0, 4);

        sequence = buffer.getInt();

        Iv = new byte[16];
        buffer.get(Iv, 0, 16);
        KeyExchangeUtil.getInstance().setIV(Iv);

        int encryptedDataLength = buffer.limit() - 4 - 4 - 16 - 12;
        encryptedData = new byte[encryptedDataLength];
        buffer.get(encryptedData, 0, encryptedDataLength);

        ICV = new byte[12];
        buffer.get(ICV, 0, 12);

        byte[] dataBeforeICV = new byte[buffer.limit() - 12];
        buffer.position(0);
        buffer.get(dataBeforeICV, 0, dataBeforeICV.length);
        byte[] dataForCompareICV = new byte[12];
        System.arraycopy(KeyExchangeUtil.getInstance().generateESPInboundICV(dataBeforeICV), 0, dataForCompareICV, 0, dataForCompareICV.length);
        if (Arrays.equals(dataForCompareICV, ICV)) {
//            Log.d(TAG, "Incoming packet has been verified");
        } else {
            Log.d(TAG, "Incoming packet has not been verified");
        }

        decryptedData = KeyExchangeUtil.getInstance().decryptESPPayload(encryptedData);

        padLength = new byte[1];
        nextHeader = new byte[1];

        System.arraycopy(decryptedData, decryptedData.length - 2, padLength, 0, 1);
        System.arraycopy(decryptedData, decryptedData.length - 1, nextHeader, 0, 1);

        int payloadLength = decryptedData.length - 2 - (int)padLength[0];
        payload = new byte[payloadLength];
        System.arraycopy(decryptedData, 0, payload, 0, payloadLength);
    }
}
