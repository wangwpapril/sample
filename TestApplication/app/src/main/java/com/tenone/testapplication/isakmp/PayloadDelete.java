package com.tenone.testapplication.isakmp;

import java.nio.ByteBuffer;

public class PayloadDelete extends PayloadBase {
    public byte[] doi;
    public byte[] protocolId;
    public byte[] spiSize;
    public byte[] spiCount;
    public byte[][] spiData;

    PayloadDelete(ByteBuffer buffer) {
        super(buffer);
        if (isValid()) {
            doi = new byte[4];
            buffer.get(doi, 0, 4);
            protocolId = new byte[1];
            buffer.get(protocolId, 0, 1);
            spiSize = new byte[1];
            buffer.get(spiSize, 0, 1);
            spiCount = new byte[2];
            buffer.get(spiCount, 0, 2);

            int count = Utils.toInt(spiCount);
            int size = (int) spiSize[0];
            spiData = new byte[count][size];
            for(int i = 0; i < count; i++) {
                byte[] spi = new byte[size];
                buffer.get(spi, 0, size);
                System.arraycopy(spi, 0, spiData[i], i*size, size);
            }
        }

    }
}
