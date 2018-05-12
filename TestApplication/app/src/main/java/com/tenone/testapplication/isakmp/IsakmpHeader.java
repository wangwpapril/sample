package com.tenone.testapplication.isakmp;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

/**
 * Created by willwang on 2018-05-03.
 */

public class IsakmpHeader {
    public static final int FLAG = 0x0001;

    private static final int INT_BUFFER_SIZE = 4;
    private static final int LONG_BUFFER_SIZE = 8;
    private static final int ADDRESS_BUFFER_SIZE = 4;
    private static final int COOKIE_LENGTH = 8;
    private static final int HEADER_TOTAL_LENGTH = 28;

    //parsing data
    public byte[] initiatorCookie = new byte[COOKIE_LENGTH];
    public byte[] responderCookie = new byte[COOKIE_LENGTH];
    public byte nextPayload;
    public byte version;
    public byte exchangeType;
    public byte flags;
    public int messageId;
    public int payloadLength;
    public byte[] headerData = new byte[HEADER_TOTAL_LENGTH];
    public boolean ready;

    //creating data
    private String sourceIp = "10.10.68.120";
    private int sourcePort = 0;
    private String destIp = "54.200.56.198";
    private int destPort = 500;
    private int nextPayloadType;


    public IsakmpHeader(String sourceIp, int sourcePort, String destIp, int destPort) {
        this.sourceIp = sourceIp;
        this.sourcePort = sourcePort;
        this.destIp = destIp;
        this.destPort = destPort;
    }

    public IsakmpHeader(ByteBuffer buffer) {
        int initPosition = buffer.position();
        buffer.get(headerData, 0, HEADER_TOTAL_LENGTH);
        buffer.position(initPosition);
        ready = true;

        buffer.get(this.initiatorCookie, 0, COOKIE_LENGTH);
        buffer.get(this.responderCookie, 0, COOKIE_LENGTH);
        nextPayload = buffer.get();
        version = buffer.get();
        exchangeType = buffer.get();
        flags = buffer.get();
        messageId = buffer.getInt();
        payloadLength = buffer.getInt();
    }

    public byte[] toData(int nextPayloadType) {
        this.nextPayloadType = nextPayloadType;
        if (!ready) {
            prepareHeader();
        }else {
            byte[] nextPayload = toBytes(nextPayloadType, 1);    // Security Association
            System.arraycopy(nextPayload, 0, headerData, 16, 1);
        }

        return headerData;
    }

    public byte[] toData(int nextPayloadType, int length, byte flag) {
        this.nextPayloadType = nextPayloadType;
        this.flags = flag;
        if (!ready) {
            prepareHeader();
        }else {
            byte[] nextPayload = toBytes(nextPayloadType, 1);    // Security Association
            System.arraycopy(nextPayload, 0, headerData, 16, 1);
            System.arraycopy(new byte[]{flag}, 0, headerData, 19, 1);
            System.arraycopy(toBytes(length, 4), 0, headerData, 24, 4);
        }

        return headerData;
    }

    private void prepareHeader() {

        initiatorCookie = generateInitiatorCookie();
        responderCookie = new byte[COOKIE_LENGTH];
        byte[] nextPayload = toBytes(nextPayloadType, 1);    // Security Association

//        nextPayload = toBytes(1, 1)[0];    // Security Association
        version |= 1 << 4;       // Major version: 1 (first 4 bits), Minor version: 0 (last 4 bits)
        exchangeType = toBytes(2, 1)[0];  // 2 - Identity Protection (Main mode)
        byte[] messageId = new byte[4];
        byte[] payloadLength = new byte[4];

        System.arraycopy(initiatorCookie, 0, headerData, 0, 8);
        System.arraycopy(responderCookie, 0, headerData, 8, 8);
        System.arraycopy(nextPayload, 0, headerData, 16, 1);
        System.arraycopy(new byte[]{version}, 0, headerData, 17, 1);
        System.arraycopy(new byte[]{exchangeType}, 0, headerData, 18, 1);
        System.arraycopy(new byte[]{flags}, 0, headerData, 19, 1);
        System.arraycopy(messageId, 0, headerData, 20, 4);
        System.arraycopy(payloadLength, 0, headerData, 24, 4);

    }

    private byte[] generateInitiatorCookie() {

        Long ct = System.currentTimeMillis();
        InetSocketAddress sa1 = new InetSocketAddress(sourceIp, sourcePort);
        InetSocketAddress sa2 = new InetSocketAddress(destIp, destPort);

        byte[] chars = new byte[30];
        System.arraycopy(sa1.getAddress().getAddress(), 0, chars, 0, ADDRESS_BUFFER_SIZE);

        System.arraycopy(toBytes(sa1.getPort()), 0, chars, 4, INT_BUFFER_SIZE);

        System.arraycopy(sa2.getAddress().getAddress(), 0, chars, 8, ADDRESS_BUFFER_SIZE);

        System.arraycopy(toBytes(sa2.getPort()), 0, chars, 12, INT_BUFFER_SIZE);

        System.arraycopy(toBytes(ct.longValue()), 0, chars, 16, LONG_BUFFER_SIZE);

        Random random = new Random();
        System.arraycopy(toBytes(random.nextInt()), 0, chars, 24, INT_BUFFER_SIZE);

        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance("SHA-1");
            byte[] value = messageDigest.digest(chars);

            StringBuilder stringBuilder = new StringBuilder();
            for (int i = 0; i < COOKIE_LENGTH; i++) {
                String c = String.format("%02x", value[i]);
                stringBuilder.append(c);
            }

//            Log.d(TAG, "value: " + stringBuilder.toString());

            byte[] ret = new byte[COOKIE_LENGTH];
            System.arraycopy(value, 0, ret, 0, COOKIE_LENGTH);
            return ret;

        } catch(NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(int sourcePort) {
        this.sourcePort = sourcePort;
    }

    public String getDestIp() {
        return destIp;
    }

    public void setDestIp(String destIp) {
        this.destIp = destIp;
    }

    public int getDestPort() {
        return destPort;
    }

    public void setDestPort(int destPort) {
        this.destPort = destPort;
    }

    private byte[] toBytes(int value) {
        return toBytes(value, INT_BUFFER_SIZE);
    }

    private byte[] toBytes(int value, int byteNumber) {
        if (byteNumber <= 0) {
            return null;
        }
        ByteBuffer byteBuffer = ByteBuffer.allocate(INT_BUFFER_SIZE);
        byteBuffer.putInt(value);
        byte[] ret = new byte[byteNumber];
        System.arraycopy(byteBuffer.array(), INT_BUFFER_SIZE - byteNumber, ret, 0, byteNumber);
        return ret;
    }

    private byte[] toBytes(long value) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(LONG_BUFFER_SIZE);
        byteBuffer.putLong(value);
        return byteBuffer.array();
    }

    public boolean isEncrypted() {
        return (flags & FLAG) == FLAG;
    }
}
